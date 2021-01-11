/*
   pam.c - PAM module functions

   Copyright (c) 2021 Andriy Sharandakov

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "config.h"

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif

/* fall back to using syslog() if pam_syslog() doesn't exist */
#ifndef HAVE_PAM_SYSLOG
#define pam_syslog(pamh, priority, format...) \
  syslog(LOG_AUTHPRIV | (priority), ##format)
#endif

int check_password(const char **username, const char **password) {
  int retval = PAM_AUTH_ERR;
  if (*username && strcmp(*username, "marvin") == 0 && *password &&
      strcmp(*password, "42") == 0) {
    retval = PAM_SUCCESS;
  }
  return retval;
}

int check_otp(const char **username, const char **otp) {
  int retval = PAM_AUTH_ERR;
  if (*otp && strcmp(*otp, "123") == 0) {
    retval = PAM_SUCCESS;
  }
  return retval;
}

int get_otp(pam_handle_t *pamh, const char **authtok, char *prompt,
            int msg_style) {
  int retval = PAM_AUTH_ERR;
  struct pam_conv *conv;
  const struct pam_message msg = {.msg_style = msg_style, .msg = prompt};
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;

  retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "pam_conv failed: %s",
               pam_strerror(pamh, retval));
    free(resp->resp);
    free(resp);
    return retval;
  }

  retval = conv->conv(1, &msgs, &resp, conv->appdata_ptr);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "pam_conv failed: %s",
               pam_strerror(pamh, retval));
    free(resp->resp);
    free(resp);
    return retval;
  }

  if (retval == PAM_SUCCESS && resp && resp->resp) {
    *authtok = resp->resp;
  } else {
    free(resp->resp);
  }
  free(resp);

  return retval;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  int retval = PAM_AUTH_ERR;
  const char *username;
  const char *password;
  const char *otp;

  const char *username_prompt = "Username: ";
  const char *password_prompt = "Password: ";
  const char *otp_prompt = "OTP: ";

  retval = pam_get_user(pamh, &username, username_prompt);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "failed to get username: %s",
               pam_strerror(pamh, retval));
    return retval;
  }

  retval = pam_get_authtok(pamh, PAM_AUTHTOK, &password, password_prompt);
  if (retval != PAM_SUCCESS && password && password[0] != '\0') {
    pam_syslog(pamh, LOG_ERR, "failed to get password: %s",
               pam_strerror(pamh, retval));
    return retval;
  }

  retval = check_password(&username, &password);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "password incorrect");
    return retval;
  }

  retval = get_otp(pamh, &otp, "OTP: ", PAM_PROMPT_ECHO_OFF);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "failed to get OTP: %s",
               pam_strerror(pamh, retval));
    return retval;
  }

  retval = check_otp(&username, &otp);
  if (retval != PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "wrong OTP");
    return retval;
  }

  return retval;
}

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  pam_syslog(pamh, LOG_INFO, "pam_sm_acct_mgmt not implemented");
  return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  pam_syslog(pamh, LOG_INFO, "pam_sm_setcred not implemented");
  return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {
  pam_syslog(pamh, LOG_INFO, "pam_sm_open_session not implemented");
  return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char **argv) {
  pam_syslog(pamh, LOG_INFO, "pam_sm_close_session not implemented");
  return PAM_SUCCESS;
}

int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                     const char **argv) {
  pam_syslog(pamh, LOG_INFO, "pam_sm_chauthtok not implemented");
  return PAM_SUCCESS;
}
