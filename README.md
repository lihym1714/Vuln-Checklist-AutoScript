# 프로젝트 개요

본 프로젝트는 **블랙박스 모의해킹(Black-box Penetration Testing)** 및 **보안 취약점 진단** 업무의 **효율성과 정확성 향상**을 목적으로 개발된 **보조 도구**입니다. 
모의해킹 및 취약점 진단은 체계적이고 반복적인 점검 과정을 요구하며, 각 진단 항목은 보안 가이드라인에 따라 정밀하게 검토되어야 합니다. 
그러나 수작업으로 진행되는 경우 진단 항목의 누락, 반복적 작업으로 인한 오류 발생, 업무 효율 저하 등 다양한 문제가 발생할 수 있습니다.

이에 본 프로젝트는 **공식 취약점 진단 가이드라인**을 기반으로 한 항목 검증을 지원하며, 진단 과정에서 반복적이고 수동적인 업무를 자동화하거나 보조함으로써 
진단자의 업무 부담을 경감하고 **일관성 있고 신뢰성 있는 검증 결과**를 확보하도록 설계되었습니다. 이를 통해 진단자는 보다 전략적인 보안 분석과 취약점 대응에 집중할 수 있으며, 
전체적인 보안 진단 품질과 효율성을 동시에 향상시킬 수 있습니다.



# Project Overview

This project is a **support tool** developed to enhance the efficiency and accuracy of **black-box penetration testing** and **security vulnerability assessments**. 
Penetration testing and vulnerability assessments require a systematic and repetitive verification process, 
where each test item must be meticulously reviewed according to established security guidelines. Manual execution of these tasks can lead to omissions, repetitive errors, and reduced operational efficiency.

Accordingly, this project is designed to **assist in verifying assessment items based on official vulnerability assessment guidelines**. 
It automates or streamlines repetitive and manual tasks during the testing process, thereby reducing the workload of security testers and ensuring **consistent and reliable verification results**. 
By leveraging this tool, testers can focus on strategic security analysis and vulnerability mitigation, ultimately improving both the quality and efficiency of security assessments.

---

# 사용법
```vi vclas.sh```
vi를 통해 vclas.sh 편집모드에 진입합니다.
```
domain="example.com"  # Change to target Domain
```
domain의 값을 대상으로 변경합니다.
```./vclas.sh```
명령어를 통해 Shell을 실행합니다.

# Usage
```vi vclas.sh```
Enter vclas.sh edit mode via vi.
```
domain="example.com"  # Change to target Domain
```
Change the domain values to target.
```./vclas.sh```
Run Shell using the above command.

---

# 설치
`Vuln-Checklist-AutoScript` 를 성공적으로 사용하기 위해서는 **python3**가 필요합니다. 다음 명령을 실행하여 설치하세요.
```
git clone https://github.com/lihym1714/Vuln-Checklist-AutoScript.git
```
```
python3 -m venv venv
source venv/bin/activate
```
가상 환경을 구성해 패키지간 충돌이 발생하지 않도록 합니다.
```pip install -r requirements.txt```
실행에 필요한 써드파티 모듈을 설치해줍니다.


다음으로 툴의 구성 요소인 subfinder와 httpx를 설치해야합니다.
subfinder와 httpx를 성공적으로 설치하기 위해서는 go1.24가 필요합니다. 다음 명령을 실행하여 설치하세요.
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```
go 다운로드 -> <https://go.dev/dl/>

# Installation
`Vuln-Checklist-AutoScript` requires **python3** to use successfull. Run the following command to install.
```
git clone https://github.com/lihym1714/Vuln-Checklist-AutoScript.git
```
```
python3 -m venv venv
source venv/bin/activate
```
Configure the virtual environment to prevent conflicts between packages.
```pip install -r requirements.txt```
Installs the third-party modules required for execution.


Next, you need to install subfinder and httpx, which are components of the tool.
You need go1.24 to install subfinder and httpx successfully. Run the following command to install.
```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```
Download go -> <https://go.dev/dl/>
