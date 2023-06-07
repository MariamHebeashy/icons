## Setup

```bash
git clone https://github.com/MariamHebeashy/icons.git
cd  icons
cp .env.example .env // Change your configurations
sudo composer install
sudo chmod -R 777 storage
sudo chmod -R 777 public
php artisan migrate
php artisan passport:install
php artisan serve
