import { Controller, ControllerState } from '@lionrockjs/mvc';
import { ControllerMixinView } from '@lionrockjs/central';
import { ControllerAccount } from '@lionrockjs/mod-auth';
import ControllerMixinAccountPassword from '../controller-mixin/AccountPassword.mjs';

export default class ControllerAccountPassword extends ControllerAccount {
  static mixins = [
    ...ControllerAccount.mixins,
    ControllerMixinAccountPassword
  ]

  constructor(request: any) {
    super(request, {});
  }

  async action_index(){
    const request = this.state.get(ControllerState.REQUEST);

    ControllerMixinView.setTemplate(this.state, 'templates/account/change-password/form', {
      user_full_name: request.session.user_meta.full_name,
      user_id: request.session.user_id,
      user_role: request.session.roles.join(","),
    })
  }

  async action_change_password_post(){

  }

  async action_change_password_done(){
    ControllerMixinView.setTemplate(this.state, 'templates/account/change-password/submit')
  }
}
