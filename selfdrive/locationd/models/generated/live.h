#pragma once
#include "rednose/helpers/ekf.h"
extern "C" {
void live_update_4(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_9(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_10(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_12(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_35(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_32(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_13(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_14(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_update_33(double *in_x, double *in_P, double *in_z, double *in_R, double *in_ea);
void live_H(double *in_vec, double *out_6719474845581148061);
void live_err_fun(double *nom_x, double *delta_x, double *out_5712253651300688127);
void live_inv_err_fun(double *nom_x, double *true_x, double *out_2610746729343656511);
void live_H_mod_fun(double *state, double *out_3854677912564870518);
void live_f_fun(double *state, double dt, double *out_2530177634384035529);
void live_F_fun(double *state, double dt, double *out_6013380908339591968);
void live_h_4(double *state, double *unused, double *out_788219138877258916);
void live_H_4(double *state, double *unused, double *out_6741644358866843071);
void live_h_9(double *state, double *unused, double *out_551227952006920006);
void live_H_9(double *state, double *unused, double *out_6982834005496433716);
void live_h_10(double *state, double *unused, double *out_3358402263224572212);
void live_H_10(double *state, double *unused, double *out_1469853183302248955);
void live_h_12(double *state, double *unused, double *out_9200833696705144544);
void live_H_12(double *state, double *unused, double *out_7362743383914436738);
void live_h_35(double *state, double *unused, double *out_3734687587933191913);
void live_H_35(double *state, double *unused, double *out_8338437657470101169);
void live_h_32(double *state, double *unused, double *out_3147211846817592599);
void live_H_32(double *state, double *unused, double *out_5767301640506343559);
void live_h_13(double *state, double *unused, double *out_3210004730012653889);
void live_H_13(double *state, double *unused, double *out_2123270871380522623);
void live_h_14(double *state, double *unused, double *out_551227952006920006);
void live_H_14(double *state, double *unused, double *out_6982834005496433716);
void live_h_33(double *state, double *unused, double *out_4694760123443593883);
void live_H_33(double *state, double *unused, double *out_5187880652831243565);
void live_predict(double *in_x, double *in_P, double *in_Q, double dt);
}