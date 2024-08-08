const localStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

// Model de usuário
require("../models/Usuario");
const Usuario = mongoose.model("usuarios");

module.exports = function (passport) {
  passport.use(
    new localStrategy(
      { usernameField: "email", passwordField: "senha" },
      (email, senha, done) => {
        // Procurar usuário pelo email
        Usuario.findOne({ email: email })
          .lean()
          .then((usuario) => {
            // Verifica se o usuário não existe
            if (!usuario) {
              return done(null, false, { message: "Conta inexistente" });
            }

            // Comparar senha fornecida com a senha armazenada no banco
            bcrypt.compare(senha, usuario.senha, (erro, batem) => {
              if (batem) {
                return done(null, usuario);
              } else {
                return done(null, false, { message: "Senha incorreta" });
              }
            });
          })
          .catch((err) => {
            return done(err);
          });
      }
    )
  );

  passport.serializeUser((usuario, done) => {
    done(null, usuario._id);
  });

  passport.deserializeUser((id, done) => {
    Usuario.findById(id)
      .lean()
      .then((usuario) => {
        done(null, usuario);
      })
      .catch((err) => {
        done(err, null);
      });
  });
};
