FROM archlinux:base-20250202.0.304438

RUN pacman -Syu --noconfirm gcc make && useradd --create-home user

USER user

WORKDIR /home/user

COPY . /home/user

RUN make

CMD ["./playground"]
