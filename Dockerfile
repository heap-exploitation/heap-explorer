FROM archlinux/archlinux:base-devel-20250209.0.306557

RUN useradd --create-home user

USER user

WORKDIR /home/user

COPY . /home/user

RUN make

CMD ["./playground"]
