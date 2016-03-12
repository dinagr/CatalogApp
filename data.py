from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from random import randint
import datetime
import random

engine = create_engine('postgresql://catalog:catalogLinuxWebServer@localhost/categorieitems')

Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)

session = DBSession()

# Cleand DB and start over

# Delete all items
items = session.query(Item).all()
for item in items:
    session.delete(item)
session.commit()

# Delete all categories
categories = session.query(Category).all()
for category in categories:
    session.delete(category)
session.commit()

# Delete all users
users = session.query(User).all()
for user in users:
    session.delete(user)
session.commit()

# Enter new data to the DB

# Create users
user1 = User(name = "dina", email="dina@gmail.com")
session.add(user1)
session.commit()
user2 = User(name = "alex", email="alex@gmail.com")
session.add(user2)
session.commit()
user3 = User(name = "bob", email="bob@gmail.com")
session.add(user3)
session.commit()

# Create categories and items

category1 = Category(name = "Soccer", user_id=1)
session.add(category1)
session.commit()
item1_1 = Item(category_id = 1, name = "Soccer Socks",
               description = "Soccer socks are extremely "
               "long. They cover shin-guards.",
               picture = "http://www.soccergarage.com/images/T/5-56.jpg",
               user_id=1)
session.add(item1_1)
session.commit()
item1_2 = Item(category_id = 1, name = "Shin-Guards",
               description = "Shin-guards protect players shins, "
               "a vulnerable part of a players body that often gets kicked.",
               user_id=2)
session.add(item1_2)
session.commit()
item1_3 = Item(category_id = 1, name = "Soccer Ball",
               description = "Soccer balls allows players to train "
               "and play individually or with friends outside of practice.",
               picture = "https://openclipart.org"
               "/image/2400px/svg_to_png/196123/1407858226.png",
               user_id=1)
session.add(item1_3)
session.commit()
category2 = Category(name = "Basketball", user_id=2)
session.add(category2)
session.commit()
item2_1 = Item(category_id = 2, name = "Basketball sleeve",
               description = "Made out of nylon and spandex, "
               "it extends from the biceps to the wrist",
               picture = "http://www.dickssportinggoods.com/graphics/"
               "product_images/pDSP1-18056254v750.jpg",
               user_id=2)
session.add(item2_1)
session.commit()
item2_2 = Item(category_id = 2, name = "Basketball uniform",
               description = " Basketball uniforms consist of a jersey "
               "that features the number and last name of the player on "
               "the back, as well as shorts and athletic shoes.",
               picture = "http://www.ciscoathletic.com/wp-content/"
               "uploads/2013/12/259_samples_lg.jpg",
               user_id=2)
session.add(item2_2)
session.commit()
item2_3 = Item(category_id = 2, name = "finger sleeve",
               description = "The use of the finger sleeve is authorized"
               "and approved by the NBA (National Basketball Association). "
               "In many cases the finger sleeve is worn for protection instead"
               " of performing some sort of taping job on the digit.",
               picture = "http://ecx.images-amazon.com/images/"
               "I/41ai-7urQRL._SY300_.jpg",
               user_id=3)
session.add(item2_3)
session.commit()
item2_4 = Item(category_id = 2, name = "Shot clock",
               description = "It is analogous with the play clock"
               "used in American and Canadian football.",
               picture = "http://cache.ultiworld.com/wordpress/"
               "wp-content/uploads/2012/09/shot_clock.jpg",
               user_id=3)
session.add(item2_4)
session.commit()
category3 = Category(name = "Baseball", user_id=1)
session.add(category3)
category4 = Category(name = "Frisbee", user_id=3)
session.add(category4)
category5 = Category(name = "Dancing", user_id=1)
session.add(category5)
item5_1 = Item(category_id = 5, name = "Ballet dancing shoes",
               description = "Ballet shoes for women",
               picture = "http://www.mywearingideas.com/wp-content/"
               "uploads/2015/05/dance-shoes-4.jpg",
               user_id=3)
session.add(item5_1)
session.commit()
item5_2 = Item(category_id = 5, name = "Steps dancing shoes",
               description = "steps dancing shoes for men and women",
               picture = "http://vitalleaders.blogs.uua.org/"
               "files/2013/11/shoes.jpg",
               user_id=3)
session.add(item5_2)
session.commit()
category6 = Category(name = "Painting", user_id=1)
session.add(category6)
session.commit()
category7 = Category(name = "Football", user_id=1)
session.add(category7)
session.commit()
category8 = Category(name = "Snowboarding", user_id=1)
session.add(category8)
session.commit()
