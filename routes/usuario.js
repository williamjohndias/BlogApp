const express = require("express");
const router = express.Router();
const mongoose = require("mongoose");
require("../models/Usuario");
const Usuario = mongoose.model("usuarios");
const bcrypt = require("bcryptjs");
const passport = require("passport");

// Adiciona um log para verificar a conexão com o banco de dados
mongoose.connection.once("open", () => {
  console.log("Conectado ao MongoDB");
});

router.get("/registro", (req, res) => {
  res.render("usuarios/registro");
});

router.post("/registro", (req, res) => {
  var erros = [];

  console.log("Recebido formulário de registro:", req.body);

  if (
    !req.body.nome ||
    typeof req.body.nome == "undefined" ||
    req.body.nome == null
  ) {
    erros.push({ texto: "Nome inválido" });
  }
  if (
    !req.body.email ||
    typeof req.body.email == "undefined" ||
    req.body.email == null
  ) {
    erros.push({ texto: "E-mail inválido" });
  }
  if (
    !req.body.senha ||
    typeof req.body.senha == "undefined" ||
    req.body.senha == null
  ) {
    erros.push({ texto: "Senha inválida" });
  }
  if (req.body.senha.length < 4) {
    erros.push({ texto: "Senha muito curta" });
  }
  if (req.body.senha != req.body.senha2) {
    erros.push({ texto: "As senhas são diferentes" });
  }
  if (erros.length > 0) {
    console.log("Erros de validação:", erros);
    res.render("usuarios/registro", { erros: erros });
  } else {
    Usuario.findOne({ email: req.body.email })
      .lean()
      .then((usuario) => {
        console.log("Resultado da busca por e-mail:", usuario);
        if (usuario) {
          console.log("E-mail já cadastrado.");
          req.flash("error_msg", "E-mail já cadastrado!");
          res.redirect("/usuarios/registro");
        } else {
          const novoUsuario = new Usuario({
            nome: req.body.nome,
            email: req.body.email,
            senha: req.body.senha,
          });

          bcrypt.genSalt(10, (erro, salt) => {
            if (erro) {
              console.error("Erro ao gerar salt:", erro);
              req.flash(
                "error_msg",
                "Houve um erro durante o salvamento do usuário"
              );
              return res.redirect("/usuarios/registro");
            }

            bcrypt.hash(novoUsuario.senha, salt, (erro, hash) => {
              if (erro) {
                console.error("Erro ao gerar hash:", erro);
                req.flash(
                  "error_msg",
                  "Houve um erro durante o salvamento do usuário"
                );
                return res.redirect("/usuarios/registro");
              }
              novoUsuario.senha = hash;

              novoUsuario
                .save()
                .then(() => {
                  req.flash("success_msg", "Usuário criado com sucesso!");
                  res.redirect("/");
                })
                .catch((err) => {
                  console.error("Erro ao salvar o usuário: ", err);
                  req.flash("error_msg", "Houve um erro ao criar o usuário!");
                  res.redirect("/usuarios/registro");
                });
            });
          });
        }
      })
      .catch((err) => {
        console.error("Erro interno: ", err);
        req.flash("error_msg", "Houve um erro interno");
        res.redirect("/usuarios/registro");
      });
  }
});

router.get("/login", (req, res) => {
  res.render("usuarios/login");
});

router.post("/login", (req, res, next) => {
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/usuarios/login",
    failureFlash: true,
  })(req, res, next);
});

router.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

module.exports = router;
