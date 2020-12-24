go generate
set RELEASE=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%
set GOOS=windows
go build -o adalanche-windows-x64-%release%.exe
set GOOS=darwin
go build -o adalanche-osx-x64-%release%
set GOOS=linux
go build -o adalanche-linux-x64-%release%
