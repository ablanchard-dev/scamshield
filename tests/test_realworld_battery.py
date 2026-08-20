"""Batterie monde-reel : de vrais scams doivent scorer > SUR, de vrais messages legitimes doivent
rester SUR. C'est le vrai-positif/vrai-negatif du produit (pas un dataset synthetique)."""
from scamshield.scorer import score_text

SCAMS = [
    "ALERTE: votre compte bancaire sera suspendu. Confirmez vos identifiants immediatement: http://secure-bnp.verif-login.ru",
    "Votre colis est en attente. Reglez les 2,99EUR de frais de douane ici: http://laposte-colis-suivi.xyz/pay",
    "Felicitations! Vous avez gagne un iPhone 15. Reclamez votre lot maintenant: http://reward-winner-fr.top/claim",
    "Bonjour, j'ai installe un logiciel espion sur votre appareil et filme des videos. Payez 900EUR en Bitcoin sinon j'envoie tout a vos contacts.",
    "Votre abonnement Netflix a expire. Mettez a jour votre moyen de paiement sous 24h: http://netflix-billing-update.info",
    "Support Microsoft: votre ordinateur est infecte par 5 virus. Appelez le 01-80-88-00-00 immediatement pour eviter la perte de donnees.",
    "Impots.gouv: vous avez droit a un remboursement de 384,52EUR. Renseignez vos coordonnees bancaires: http://impots-remboursement.gouv-fr.net",
    "URGENT maman/papa j'ai casse mon telephone, voici mon nouveau numero. Peux-tu m'envoyer 250EUR par PCS, je te rembourse ce soir.",
    "Votre carte SFR sera desactivee. Cliquez pour eviter la coupure et confirmer votre identite: http://sfr-mon-compte.secure-verif.cc",
    "Investissement crypto garanti +300% en 30 jours. Places limitees. Inscrivez-vous avec votre wallet: http://crypto-profit-fr.io",
    "Amende non payee: 68EUR. Reglez sous 48h pour eviter la majoration a 180EUR: http://amendes-gouv-paiement.xyz",
]
LEGIT = [
    "Salut, on se voit demain a 14h pour le cafe ? j'ai reserve la table",
    "Bonjour, veuillez trouver ci-joint le compte rendu de la reunion de lundi. Bonne journee.",
    "Ton colis Amazon a ete livre. Tu peux laisser un avis dans l'application si tu veux.",
    "Rappel: rendez-vous chez le dentiste jeudi 10h. Pour annuler, rappelez le cabinet.",
    "Merci pour ton virement, bien recu. On se cale pour le resto le week-end prochain ?",
    "La reunion d'equipe est deplacee a 15h en salle B. Ordre du jour en piece jointe.",
    "Joyeux anniversaire !! On pense fort a toi, gros bisous de toute la famille",
    "Votre commande #48213 a bien ete expediee et arrivera entre mardi et jeudi.",
    "Coucou, tu peux me renvoyer la recette des lasagnes stp ? je l'ai perdue",
    "Newsletter: nos nouveaux horaires d'ouverture pour la rentree, et les ateliers du mois.",
    "Bonjour, suite a notre entretien, je vous confirme ma disponibilite pour le poste. Cordialement.",
]

def band(s):
    return "SUR" if s < 25 else "DOUTEUX" if s < 60 else "RISQUE"

def _run():
    print("\n--- SCAMS (doivent etre > SUR) ---")
    scam_caught = 0
    for t in SCAMS:
        s, *_ = score_text(t); b = band(s)
        if b != "SUR": scam_caught += 1
        print(f"  [{b:8}] {s:3}/100  {t[:60]}")
    print(f"  => {scam_caught}/{len(SCAMS)} scams detectes")
    print("\n--- LEGIT (doivent rester SUR) ---")
    legit_ok = 0
    for t in LEGIT:
        s, *_ = score_text(t); b = band(s)
        if b == "SUR": legit_ok += 1
        print(f"  [{b:8}] {s:3}/100  {t[:60]}")
    print(f"  => {legit_ok}/{len(LEGIT)} legit corrects (pas de faux positif)")
    return scam_caught, legit_ok

def test_battery():
    # Le README annonce publiquement 11/11 et 11/11. Le test doit DEFENDRE ce chiffre :
    # un seuil a ">= 10" laissait passer une regression qui rendait le README faux.
    scam, legit = _run()
    assert scam == len(SCAMS), f"{scam}/{len(SCAMS)} scams detectes, le README annonce {len(SCAMS)}/{len(SCAMS)}"
    assert legit == len(LEGIT), f"{legit}/{len(LEGIT)} legit corrects, le README annonce {len(LEGIT)}/{len(LEGIT)} sans faux positif"

if __name__ == "__main__":
    _run()
