# DLL-injector

워게임을 풀면서 공부해본 DLL 인젝션 기법을 기반으로 DLL-injector를 직접 구현해봤습니다.

제가 풀었던 문제에서는 굳이 DLL-injector가 필요없긴 했지만

앞으로 유용하게 사용할수 있을것같은 도구라고 생각합니다.


# 사용법

이 레포트리지는 프로젝트 파일 전체를 올린것이고

my-DLL-injector/my_DLL-Injector/x64/Release/
위의 경로에있는 실행파일이 실제 프로그램입니다.

설치한뒤 "무조건" 관리자 권한으로 cmd를 켠뒤, 위의 디렉토리로 이동해서 실행시키거나 절대 경로를 사용해서 실행시킬수 있는데
실행시킬때 첫번째 인자는 인젝션을 진행할 프로그램의 pid를 입력해주고 두번째 인자는 인젝션할 dll파일의 절대경로를 입력해주면 인젝션이 진행됩니다.
