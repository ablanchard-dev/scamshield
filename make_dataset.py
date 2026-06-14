"""Build a labeled French scam/ham benchmark for SCAMShield.

This is a *synthetic, templated* benchmark, generated deterministically (fixed
seed) so the dataset is reproducible and the metrics it produces are honest
about what they measure: the pipeline's ability to separate realistic scam
patterns from legitimate messages — not real-world accuracy on live traffic.

Run:  python make_dataset.py  ->  writes data/dataset.csv  (columns: text,label)
      label 1 = scam/phishing, 0 = legitimate.
"""

import csv
import os
import random

SEED = 42
OUT = os.path.join(os.path.dirname(__file__), "data", "dataset.csv")

# --- slot pools -------------------------------------------------------------
BANKS = ["votre banque", "la Société Générale", "le Crédit Agricole", "BNP Paribas", "LCL", "la Caisse d'Épargne"]
BRANDS = ["Amazon", "Netflix", "PayPal", "Microsoft", "Apple", "La Poste", "Chronopost", "DHL", "Free", "Orange"]
ADMINS = ["les Impôts", "l'URSSAF", "l'Assurance Maladie (Ameli)", "la CAF", "la DGFiP", "le Trésor Public"]
CARRIERS = ["La Poste", "Chronopost", "DHL", "Colissimo", "UPS"]
AMOUNTS = ["2,99€", "1,99€", "49€", "129€", "350€", "1000€", "9 500€"]
LINKS = ["http://secure-{b}-verif.com", "http://{b}-support.win", "http://espace-{b}.co", "https://maj-{b}.info"]
DELAYS = ["sous 24h", "avant minuit", "dans l'heure", "sous 48h", "immédiatement"]
NAMES = ["Alex", "Marie", "Thomas", "Julie", "Karim", "Sophie", "Lucas", "Nadia", "Hugo", "Inès", "Paul", "Léa"]
FIRST = ["Bonjour", "Salut", "Coucou", "Hello", "Hey"]


def link(brandword):
    b = brandword.lower().replace(" ", "").replace("'", "").replace("é", "e").replace("è", "e")[:12]
    return random.choice(LINKS).format(b=b)


# --- scam generators (label 1) ---------------------------------------------
def scam_bank():
    b = random.choice(BANKS)
    return random.choice([
        f"Message de {b} : connexion suspecte détectée. Validez votre identité {random.choice(DELAYS)} : {link(b)}",
        f"{b.capitalize()} : votre compte sera suspendu {random.choice(DELAYS)}. Réactivez-le ici : {link(b)}",
        f"Alerte sécurité {b} : un virement de {random.choice(AMOUNTS)} est en attente, confirmez : {link(b)}",
    ])


def scam_delivery():
    b = random.choice(CARRIERS)
    return random.choice([
        f"Votre colis {b} est retenu. Réglez les frais de douane de {random.choice(AMOUNTS)} : {link(b)}",
        f"{b} : adresse incomplète, votre colis sera retourné {random.choice(DELAYS)}. Mettez à jour : {link(b)}",
        f"Suivi {b} : un paiement de {random.choice(AMOUNTS)} est requis pour la livraison. {link(b)}",
    ])


def scam_admin():
    a = random.choice(ADMINS)
    return random.choice([
        f"{a} : un remboursement de {random.choice(AMOUNTS)} vous attend. Renseignez votre RIB {random.choice(DELAYS)} : {link('gouv')}",
        f"Avis de {a} : pénalité {random.choice(DELAYS)} si votre dossier n'est pas régularisé : {link('gouv')}",
        f"{a} vous informe d'une amende impayée de {random.choice(AMOUNTS)}. Payez maintenant : {link('gouv')}",
    ])


def scam_prize():
    b = random.choice(BRANDS)
    return random.choice([
        f"Félicitations ! Vous avez gagné une carte cadeau {b} de {random.choice(AMOUNTS)}. Réclamez-la : {link(b)}",
        f"Vous avez été tiré au sort pour un iPhone 15. Répondez {random.choice(DELAYS)} pour le recevoir : {link(b)}",
        f"Bravo ! Votre numéro a gagné {random.choice(AMOUNTS)}. Cliquez {random.choice(DELAYS)} : {link(b)}",
    ])


def scam_otp():
    return random.choice([
        f"Code OTP {random.randint(100000,999999)} – Ne le partagez avec personne (répondez pour confirmer).",
        f"Votre code de vérification est {random.randint(1000,9999)}. Communiquez-le à notre conseiller pour valider.",
        f"Sécurité : un agent va vous appeler, donnez-lui le code {random.randint(100000,999999)} pour débloquer votre compte.",
    ])


def scam_crypto():
    return random.choice([
        f"Investissez {random.choice(AMOUNTS)} en Bitcoin et gagnez x10 garanti. Inscrivez-vous : {link('crypto')}",
        f"Opportunité crypto exclusive : envoyez à 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa pour doubler votre mise.",
        f"Votre portefeuille crypto a été crédité de {random.choice(AMOUNTS)}. Activez le retrait : {link('wallet')}",
    ])


def scam_phone():
    return random.choice([
        f"Rappelez d'urgence le 0{random.randint(810,899)} {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)} concernant votre dossier.",
        "Numéro surtaxé : votre colis vous attend, appelez vite.",
        f"+33 7 56 {random.randint(10,99)} {random.randint(10,99)} {random.randint(10,99)} : votre carte bancaire a été bloquée, rappelez.",
    ])


def scam_support():
    b = random.choice(BRANDS)
    return random.choice([
        f"Support {b} : mise à jour de sécurité obligatoire. Connectez-vous {random.choice(DELAYS)} : {link(b)}",
        f"{b} : connexion depuis un nouvel appareil. Si ce n'est pas vous, sécurisez votre compte : {link(b)}",
        f"Votre abonnement {b} a expiré. Renouvelez {random.choice(DELAYS)} pour {random.choice(AMOUNTS)} : {link(b)}",
    ])


def scam_romance():
    return random.choice([
        "Mon amour, je suis bloqué à l'étranger, peux-tu m'envoyer 500€ par Western Union pour mon billet ?",
        "Notre héritage est bloqué à la douane, il faut régler des frais pour le débloquer, je te rembourse vite.",
        "Je t'aime, mais j'ai une urgence familiale. Envoie-moi de quoi payer l'hôpital, je n'ai que toi.",
        "Bonjour, votre profil m'a tapé dans l'œil. Discutons sur WhatsApp, voici mon numéro privé.",
    ])


SCAM_GENS = [scam_bank, scam_delivery, scam_admin, scam_prize, scam_otp,
             scam_crypto, scam_phone, scam_support, scam_romance]


# --- ham generators (label 0) — combinatorial slots for variety -------------
WORK_TOPICS = [
    "on déploie en préprod cet après-midi, je te tiens au courant.",
    "le compte-rendu de la réunion est envoyé, objectifs à 92 %.",
    "café d'équipe jeudi 10h en salle A2, pense à réserver le projecteur.",
    "mise à jour des congés dans le SIRH avant vendredi, merci.",
    "la démo client est décalée à 14h, je t'envoie le nouveau créneau.",
    "j'ai relu ta PR, deux petits commentaires mineurs, sinon c'est bon.",
    "le rapport hebdo est dans le drive partagé, jette un œil quand tu peux.",
    "on fait un point rapide sur le sprint demain matin, 9h30 ?",
    "le ticket #214 est résolu, j'ai poussé le correctif en recette.",
    "merci pour ton aide hier, le bug de prod est réglé.",
]
PERSO_TOPICS = [
    "on se voit toujours samedi pour le ciné ? Séance de 20h.",
    "pense à acheter du pain en rentrant, merci !",
    "rappel : rendez-vous médecin lundi 15h.",
    "voici les photos du week-end, à très vite.",
    "bon anniversaire ! On t'appelle ce soir.",
    "tu veux qu'on covoiture demain pour aller au boulot ?",
    "le resto de ce soir est réservé pour 19h30, à tout à l'heure.",
    "n'oublie pas de récupérer les enfants à 16h30.",
    "j'ai trouvé un bon plan pour les vacances, je t'envoie le lien après.",
    "merci pour le cadeau, ça m'a fait super plaisir !",
]
DELIVERY_OK = [
    "votre colis {c} a été livré dans votre boîte aux lettres.",
    "{c} : votre commande arrive demain entre 9h et 13h, aucune action requise.",
    "merci pour votre commande, le suivi {c} est dans votre espace client habituel.",
    "votre retour {c} a bien été pris en charge, remboursement sous 5 jours.",
]
ADMIN_OK = [
    "votre relevé est disponible dans l'application, aucun incident à signaler.",
    "confirmation d'inscription au webinaire de jeudi, le lien est dans votre espace.",
    "facture réglée, merci pour votre confiance.",
    "votre déclaration a bien été enregistrée, aucune démarche supplémentaire n'est nécessaire.",
    "votre rendez-vous en agence est confirmé pour mardi 11h.",
]
NEWS = [
    "Newsletter {b} : découvrez nos nouveautés du mois, désinscription en bas de page.",
    "votre résumé hebdo {b} est prêt, bonne lecture.",
    "mise à jour produit : de nouvelles fonctionnalités sont disponibles dans votre tableau de bord.",
    "{b} fête ses 10 ans : merci d'être client, aucune action de votre part.",
]


def ham_work():
    return f"{random.choice(FIRST)} {random.choice(NAMES)}, {random.choice(WORK_TOPICS)}"


def ham_perso():
    return f"{random.choice(FIRST)} {random.choice(NAMES)}, {random.choice(PERSO_TOPICS)}"


def ham_legit_delivery():
    return random.choice(DELIVERY_OK).format(c=random.choice(CARRIERS))


def ham_legit_admin():
    return random.choice(ADMIN_OK)


def ham_newsletter():
    return random.choice(NEWS).format(b=random.choice(BRANDS))


HAM_GENS = [ham_work, ham_perso, ham_legit_delivery, ham_legit_admin, ham_newsletter]


def _fill(gens, target):
    rows = set()
    for gen in gens:
        made, tries = 0, 0
        while made < target and tries < target * 60:
            text = gen()
            tries += 1
            if text not in rows:
                rows.add(text)
                made += 1
    return rows


def build(n_per_scam=27, n_per_ham=49):
    random.seed(SEED)
    scam = _fill(SCAM_GENS, n_per_scam)
    ham = _fill(HAM_GENS, n_per_ham)
    rows = [(t, 1) for t in scam] + [(t, 0) for t in ham]
    random.shuffle(rows)
    return rows


def main():
    rows = build()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)
    scam = sum(1 for _, y in rows if y == 1)
    print(f"Wrote {len(rows)} rows to {OUT}  (scam={scam}, ham={len(rows) - scam})")


if __name__ == "__main__":
    main()
