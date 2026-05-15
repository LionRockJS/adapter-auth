import ControllerAccountPassword from './controller/AccountPassword.mjs';
import ControllerMixinAccountPassword from './controller-mixin/AccountPassword.mjs';
import IdentifierPassword from './identifier/Password.mjs';
import ModelIdentifierPassword from './model/IdentifierPassword.mjs';

import ConfigAuth from './config/auth.mjs';

export default {
  filename: import.meta.url,
  configs: {
    auth: ConfigAuth,
  }
}

export {
  ControllerAccountPassword,
  ControllerMixinAccountPassword,
  IdentifierPassword,
  ModelIdentifierPassword,
};
