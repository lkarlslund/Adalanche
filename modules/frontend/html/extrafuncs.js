function normalize(value, min, max, newmin, newmax) {
    return (value - min) * (newmax - newmin) / (max - min) + newmin;
}
