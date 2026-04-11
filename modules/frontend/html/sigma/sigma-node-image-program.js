(function () {
  const SigmaGlobal = (typeof window !== "undefined" && window.Sigma) ? window.Sigma : null;
  if (!SigmaGlobal) return;

  const POINTS = 1;
  const ATTRIBUTES = 10;
  const MAX_TEXTURE_SIZE = 192;
  const MAX_CANVAS_WIDTH = 3072;

  const INT8 = new Int8Array(4);
  const INT32 = new Int32Array(INT8.buffer, 0, 1);
  const FLOAT32 = new Float32Array(INT8.buffer, 0, 1);
  const RGBA_TEST_REGEX = /^\s*rgba?\s*\(/;
  const RGBA_EXTRACT_REGEX = /^\s*rgba?\s*\(\s*([0-9]*)\s*,\s*([0-9]*)\s*,\s*([0-9]*)(?:\s*,\s*(.*)?)?\)\s*$/;
  const FLOAT_COLOR_CACHE = Object.create(null);

  const VERTEX_SHADER_SOURCE = [
    "attribute vec2 a_position;",
    "attribute float a_size;",
    "attribute vec4 a_color;",
    "attribute vec4 a_texture;",
    "attribute vec4 a_borderColor;",
    "attribute float a_borderWidth;",
    "uniform float u_ratio;",
    "uniform float u_scale;",
    "uniform mat3 u_matrix;",
    "varying vec4 v_color;",
    "varying vec4 v_borderColor;",
    "varying float v_border;",
    "varying float v_borderWidth;",
    "varying vec4 v_texture;",
    "const float bias = 255.0 / 254.0;",
    "void main() {",
    "  gl_Position = vec4((u_matrix * vec3(a_position, 1)).xy, 0, 1);",
    "  gl_PointSize = a_size * u_ratio * u_scale * 2.0;",
    "  v_border = (1.0 / u_ratio) * (0.5 / a_size);",
    "  v_borderWidth = a_borderWidth;",
    "  v_color = a_color;",
    "  v_color.a *= bias;",
    "  v_borderColor = a_borderColor;",
    "  v_borderColor.a *= bias;",
    "  v_texture = a_texture;",
    "}",
  ].join("\n");

  const FRAGMENT_SHADER_SOURCE = [
    "precision mediump float;",
    "varying vec4 v_color;",
    "varying vec4 v_borderColor;",
    "varying float v_border;",
    "varying float v_borderWidth;",
    "varying vec4 v_texture;",
    "uniform sampler2D u_atlas;",
    "const float radius = 0.5;",
    "const float iconScale = 0.8;",
    "const vec4 transparent = vec4(0.0, 0.0, 0.0, 0.0);",
    "void main(void) {",
    "  vec4 color;",
    "  if (v_texture.w > 0.0) {",
    "    vec2 iconCoord = (gl_PointCoord - vec2(0.5, 0.5)) / iconScale + vec2(0.5, 0.5);",
    "    vec4 texel = transparent;",
    "    if (iconCoord.x >= 0.0 && iconCoord.x <= 1.0 && iconCoord.y >= 0.0 && iconCoord.y <= 1.0) {",
    "      texel = texture2D(u_atlas, v_texture.xy + iconCoord * v_texture.zw, -1.0);",
    "    }",
    "    color = vec4(mix(v_color, texel, texel.a).rgb, max(texel.a, v_color.a));",
    "  } else {",
    "    color = v_color;",
    "  }",
    "  vec2 m = gl_PointCoord - vec2(0.5, 0.5);",
    "  float dist = length(m);",
    "  float innerRadius = max(0.0, radius - v_borderWidth);",
    "  if (dist < innerRadius) {",
    "    gl_FragColor = color;",
    "  } else if (dist < radius - v_border) {",
    "    gl_FragColor = v_borderWidth > 0.0 ? v_borderColor : color;",
    "  } else if (dist < radius) {",
    "    vec4 edgeColor = v_borderWidth > 0.0 ? v_borderColor : color;",
    "    gl_FragColor = mix(transparent, edgeColor, (radius - dist) / v_border);",
    "  } else {",
    "    gl_FragColor = transparent;",
    "  }",
    "}",
  ].join("\n");

  function loadShader(type, gl, source) {
    const glType = type === "VERTEX" ? gl.VERTEX_SHADER : gl.FRAGMENT_SHADER;
    const shader = gl.createShader(glType);
    if (!shader) throw new Error("WorkspaceSigmaNodeImageProgram: failed to create shader");
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      const infoLog = gl.getShaderInfoLog(shader);
      gl.deleteShader(shader);
      throw new Error(`WorkspaceSigmaNodeImageProgram: shader compile failed\n${infoLog || ""}\n${source}`);
    }
    return shader;
  }

  function loadProgram(gl, shaders) {
    const program = gl.createProgram();
    if (!program) throw new Error("WorkspaceSigmaNodeImageProgram: failed to create program");
    for (const shader of shaders) gl.attachShader(program, shader);
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      gl.deleteProgram(program);
      throw new Error("WorkspaceSigmaNodeImageProgram: failed to link program");
    }
    return program;
  }

  function parseColor(val) {
    const value = String(val || "#000000");
    let r = 0;
    let g = 0;
    let b = 0;
    let a = 1;
    if (value[0] === "#") {
      if (value.length === 4) {
        r = parseInt(value.charAt(1) + value.charAt(1), 16);
        g = parseInt(value.charAt(2) + value.charAt(2), 16);
        b = parseInt(value.charAt(3) + value.charAt(3), 16);
      } else {
        r = parseInt(value.slice(1, 3), 16);
        g = parseInt(value.slice(3, 5), 16);
        b = parseInt(value.slice(5, 7), 16);
      }
      if (value.length === 9) {
        a = parseInt(value.slice(7, 9), 16) / 255;
      }
    } else if (RGBA_TEST_REGEX.test(value)) {
      const match = value.match(RGBA_EXTRACT_REGEX);
      if (match) {
        r = +match[1];
        g = +match[2];
        b = +match[3];
        if (match[4]) a = +match[4];
      }
    }
    return { r, g, b, a };
  }

  function floatColor(value) {
    const key = String(value || "#000000");
    if (typeof FLOAT_COLOR_CACHE[key] !== "undefined") return FLOAT_COLOR_CACHE[key];
    const parsed = parseColor(key);
    const { r, g, b } = parsed;
    let { a } = parsed;
    a = (a * 255) | 0;
    INT32[0] = ((a << 24) | (b << 16) | (g << 8) | r) & 0xfeffffff;
    const color = FLOAT32[0];
    FLOAT_COLOR_CACHE[key] = color;
    return color;
  }

  function createWorkspaceSigmaNodeImageProgram() {
    const rebindTextureFns = [];
    const images = Object.create(null);
    let textureImage = null;
    let hasReceivedImages = false;
    let pendingImagesFrameID;
    let writePositionX = 0;
    let writePositionY = 0;
    let writeRowHeight = 0;

    function loadImage(imageSource) {
      if (!imageSource || images[imageSource]) return;
      const image = new Image();
      image.addEventListener("load", () => {
        images[imageSource] = { status: "pending", image };
        if (typeof pendingImagesFrameID !== "number") {
          pendingImagesFrameID = window.requestAnimationFrame(() => finalizePendingImages());
        }
      });
      image.addEventListener("error", () => {
        images[imageSource] = { status: "error" };
      });
      images[imageSource] = { status: "loading" };
      image.setAttribute("crossOrigin", "");
      image.src = imageSource;
    }

    function finalizePendingImages() {
      pendingImagesFrameID = undefined;
      const pendingImages = [];
      for (const id of Object.keys(images)) {
        const state = images[id];
        if (state && state.status === "pending") {
          pendingImages.push({
            id,
            image: state.image,
            size: Math.min(state.image.width, state.image.height) || 1,
          });
        }
      }
      if (pendingImages.length === 0) return;

      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      let totalWidth = hasReceivedImages && textureImage ? textureImage.width : 0;
      let totalHeight = hasReceivedImages && textureImage ? textureImage.height : 0;
      let xOffset = writePositionX;
      let yOffset = writePositionY;

      function drawRow(rowImages) {
        if (!ctx) return;
        if (canvas.width !== totalWidth || canvas.height !== totalHeight) {
          canvas.width = Math.min(MAX_CANVAS_WIDTH, totalWidth || 1);
          canvas.height = totalHeight || 1;
          if (hasReceivedImages && textureImage) {
            ctx.putImageData(textureImage, 0, 0);
          }
        }
        for (const { id, image, size } of rowImages) {
          const imageSizeInTexture = Math.min(MAX_TEXTURE_SIZE, size);
          let dx = 0;
          let dy = 0;
          if ((image.width || 0) > (image.height || 0)) dx = (image.width - image.height) / 2;
          else dy = (image.height - image.width) / 2;
          ctx.drawImage(image, dx, dy, size, size, xOffset, yOffset, imageSizeInTexture, imageSizeInTexture);
          images[id] = {
            status: "ready",
            x: xOffset,
            y: yOffset,
            width: imageSizeInTexture,
            height: imageSizeInTexture,
          };
          xOffset += imageSizeInTexture;
        }
        hasReceivedImages = true;
        textureImage = ctx.getImageData(0, 0, canvas.width, canvas.height);
      }

      let rowImages = [];
      for (const pendingImage of pendingImages) {
        const imageSizeInTexture = Math.min(pendingImage.size, MAX_TEXTURE_SIZE);
        if (writePositionX + imageSizeInTexture > MAX_CANVAS_WIDTH) {
          if (rowImages.length > 0) {
            totalWidth = Math.max(writePositionX, totalWidth);
            totalHeight = Math.max(writePositionY + writeRowHeight, totalHeight);
            drawRow(rowImages);
            rowImages = [];
            writeRowHeight = 0;
          }
          writePositionX = 0;
          writePositionY = totalHeight;
          xOffset = 0;
          yOffset = totalHeight;
        }
        rowImages.push(pendingImage);
        writePositionX += imageSizeInTexture;
        writeRowHeight = Math.max(writeRowHeight, imageSizeInTexture);
      }

      totalWidth = Math.max(writePositionX, totalWidth);
      totalHeight = Math.max(writePositionY + writeRowHeight, totalHeight);
      drawRow(rowImages);
      rebindTextureFns.forEach((fn) => fn());
    }

    return class WorkspaceSigmaNodeImageProgram {
      constructor(gl, renderer) {
        this.points = POINTS;
        this.attributes = ATTRIBUTES;
        this.gl = gl;
        this.array = new Float32Array();
        const buffer = gl.createBuffer();
        if (!buffer) throw new Error("WorkspaceSigmaNodeImageProgram: failed to create buffer");
        this.buffer = buffer;
        gl.bindBuffer(gl.ARRAY_BUFFER, this.buffer);
        this.vertexShader = loadShader("VERTEX", gl, VERTEX_SHADER_SOURCE);
        this.fragmentShader = loadShader("FRAGMENT", gl, FRAGMENT_SHADER_SOURCE);
        this.program = loadProgram(gl, [this.vertexShader, this.fragmentShader]);
        this.positionLocation = gl.getAttribLocation(this.program, "a_position");
        this.sizeLocation = gl.getAttribLocation(this.program, "a_size");
        this.colorLocation = gl.getAttribLocation(this.program, "a_color");
        this.textureLocation = gl.getAttribLocation(this.program, "a_texture");
        this.borderColorLocation = gl.getAttribLocation(this.program, "a_borderColor");
        this.borderWidthLocation = gl.getAttribLocation(this.program, "a_borderWidth");
        this.matrixLocation = gl.getUniformLocation(this.program, "u_matrix");
        this.ratioLocation = gl.getUniformLocation(this.program, "u_ratio");
        this.scaleLocation = gl.getUniformLocation(this.program, "u_scale");
        this.atlasLocation = gl.getUniformLocation(this.program, "u_atlas");
        if (!this.matrixLocation || !this.ratioLocation || !this.scaleLocation || !this.atlasLocation) {
          throw new Error("WorkspaceSigmaNodeImageProgram: failed to resolve uniform locations");
        }
        rebindTextureFns.push(() => {
          if (this && this.rebindTexture) this.rebindTexture();
          if (renderer && renderer.refresh) renderer.refresh();
        });
        textureImage = new ImageData(1, 1);
        this.texture = gl.createTexture();
        gl.bindTexture(gl.TEXTURE_2D, this.texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE, new Uint8Array([0, 0, 0, 0]));
        this.bind();
      }

      allocate(capacity) {
        this.array = new Float32Array(this.points * this.attributes * capacity);
      }

      bufferData() {
        this.gl.bufferData(this.gl.ARRAY_BUFFER, this.array, this.gl.DYNAMIC_DRAW);
      }

      hasNothingToRender() {
        return this.array.length === 0;
      }

      bind() {
        const gl = this.gl;
        gl.bindBuffer(gl.ARRAY_BUFFER, this.buffer);
        gl.enableVertexAttribArray(this.positionLocation);
        gl.enableVertexAttribArray(this.sizeLocation);
        gl.enableVertexAttribArray(this.colorLocation);
        gl.enableVertexAttribArray(this.textureLocation);
        gl.enableVertexAttribArray(this.borderColorLocation);
        gl.enableVertexAttribArray(this.borderWidthLocation);
        gl.vertexAttribPointer(this.positionLocation, 2, gl.FLOAT, false, this.attributes * Float32Array.BYTES_PER_ELEMENT, 0);
        gl.vertexAttribPointer(this.sizeLocation, 1, gl.FLOAT, false, this.attributes * Float32Array.BYTES_PER_ELEMENT, 8);
        gl.vertexAttribPointer(this.colorLocation, 4, gl.UNSIGNED_BYTE, true, this.attributes * Float32Array.BYTES_PER_ELEMENT, 12);
        gl.vertexAttribPointer(this.textureLocation, 4, gl.FLOAT, false, this.attributes * Float32Array.BYTES_PER_ELEMENT, 16);
        gl.vertexAttribPointer(this.borderColorLocation, 4, gl.UNSIGNED_BYTE, true, this.attributes * Float32Array.BYTES_PER_ELEMENT, 32);
        gl.vertexAttribPointer(this.borderWidthLocation, 1, gl.FLOAT, false, this.attributes * Float32Array.BYTES_PER_ELEMENT, 36);
      }

      process(data, hidden, offset) {
        const array = this.array;
        let i = offset * POINTS * ATTRIBUTES;
        const imageSource = data && typeof data.image === "string" ? data.image : "";
        const imageState = imageSource && images[imageSource];
        if (imageSource && !imageState) loadImage(imageSource);
        if (hidden) {
          array[i++] = 0; array[i++] = 0; array[i++] = 0; array[i++] = 0;
          array[i++] = 0; array[i++] = 0; array[i++] = 0; array[i++] = 0;
          array[i++] = 0; array[i++] = 0;
          return;
        }
        array[i++] = Number(data.x || 0);
        array[i++] = Number(data.y || 0);
        array[i++] = Number(data.size || 0);
        array[i++] = floatColor(data.color || "#6c757d");
        if (imageState && imageState.status === "ready" && textureImage) {
          const width = textureImage.width || 1;
          const height = textureImage.height || 1;
          array[i++] = imageState.x / width;
          array[i++] = imageState.y / height;
          array[i++] = imageState.width / width;
          array[i++] = imageState.height / height;
        } else {
          array[i++] = 0; array[i++] = 0; array[i++] = 0; array[i++] = 0;
        }
        array[i++] = floatColor(data.borderColor || "rgba(0,0,0,0)");
        array[i++] = Math.max(0, Math.min(0.45, Number(data.borderWidth || 0)));
      }

      render(params) {
        if (this.hasNothingToRender()) return;
        this.latestRenderParams = params;
        const gl = this.gl;
        gl.useProgram(this.program);
        gl.activeTexture(gl.TEXTURE0);
        gl.bindTexture(gl.TEXTURE_2D, this.texture);
        gl.uniform1f(this.ratioLocation, 1 / Math.sqrt(params.ratio));
        gl.uniform1f(this.scaleLocation, params.scalingRatio);
        gl.uniformMatrix3fv(this.matrixLocation, false, params.matrix);
        gl.uniform1i(this.atlasLocation, 0);
        gl.drawArrays(gl.POINTS, 0, this.array.length / ATTRIBUTES);
      }

      rebindTexture() {
        if (!textureImage) return;
        const gl = this.gl;
        gl.bindTexture(gl.TEXTURE_2D, this.texture);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, textureImage);
        gl.generateMipmap(gl.TEXTURE_2D);
        if (this.latestRenderParams) {
          this.bind();
          this.bufferData();
          this.render(this.latestRenderParams);
        }
      }
    };
  }

  window.createWorkspaceSigmaNodeImageProgram = createWorkspaceSigmaNodeImageProgram;
}());
