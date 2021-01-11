[![Build Status](https://travis-ci.org/ashway83/pam-sample.svg?branch=main)](https://travis-ci.org/ashway83/pam-sample)

## About The Project

This is a sample PAM module project that can be used as a template for your future PAM modules.

## Getting Started

To get a local copy and build the project follow the steps.

### Prerequisites

This project uses Autotools and Libtool for building. Please make sure the following packages are installed:

* autoconf
* automake
* libtool

### Build Instructions

1. Clone the repo
   ```sh
   git clone https://github.com/ashway83/pam-sample.git
   ```
2. Generate configure script and Makefiles
   ```
   ./autogen.sh
   ```
3. Build
   ```
   ./configure
   make
   ```

## Usage

The PAM configuration files are located in `/etc/pam.d/` directory. Here is a very basic snippet to test authentication.
```
auth     sufficient     pam_sample.so
```
You can use `pamtester` or `pam_test` for testing and troubleshooting.

## Resources

* [The Linux-PAM Guides](http://www.linux-pam.org/Linux-PAM-html/)
* [pamtester](http://pamtester.sourceforge.net)
* [pam_test](https://github.com/pbrezina/pam-test)

## License

Distributed under the MIT License. See `LICENSE` for more information.
