#pragma once
#include "rednose/helpers/ekf.h"
extern "C" {
void car_update_25(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_24(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_30(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_26(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_27(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_29(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_28(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_update_31(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void car_err_fun(double *nom_x, double *delta_x, double *out_5038548064199113645);
void car_inv_err_fun(double *nom_x, double *true_x, double *out_422841015862407477);
void car_H_mod_fun(double *state, double *out_6956924357666609552);
void car_f_fun(double *state, double dt, double *out_6046962197957559382);
void car_F_fun(double *state, double dt, double *out_5575791160268656463);
void car_h_25(double *state, double *unused, double *out_2070534776185495952);
void car_H_25(double *state, double *unused, double *out_1228788828886386488);
void car_h_24(double *state, double *unused, double *out_4551797051972281038);
void car_H_24(double *state, double *unused, double *out_3640026036141320364);
void car_h_30(double *state, double *unused, double *out_480942784515735960);
void car_H_30(double *state, double *unused, double *out_3298907501241221710);
void car_h_26(double *state, double *unused, double *out_6954200649912964853);
void car_H_26(double *state, double *unused, double *out_2512714489987669736);
void car_h_27(double *state, double *unused, double *out_966251275258836733);
void car_H_27(double *state, double *unused, double *out_5473670813041646621);
void car_h_29(double *state, double *unused, double *out_1424452637417398395);
void car_H_29(double *state, double *unused, double *out_2788676156926829526);
void car_h_28(double *state, double *unused, double *out_4035421992402008912);
void car_H_28(double *state, double *unused, double *out_7871075173996360100);
void car_h_31(double *state, double *unused, double *out_1795340713900990063);
void car_H_31(double *state, double *unused, double *out_3138922592221021212);
void car_predict(double *in_x, double *in_P, double *in_Q, double dt);
void car_set_mass(double x);
void car_set_rotational_inertia(double x);
void car_set_center_to_front(double x);
void car_set_center_to_rear(double x);
void car_set_stiffness_front(double x);
void car_set_stiffness_rear(double x);
}