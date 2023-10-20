﻿// <auto-generated />
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using cu.ApiBasics.Lesvoorbeeld.Avond.Infrastructure.Data;

#nullable disable

namespace cu.ApiBasics.Lesvoorbeeld.Avond.Infrastructure.Migrations
{
    [DbContext(typeof(ApplicationDbContext))]
    partial class ApplicationDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "6.0.23")
                .HasAnnotation("Relational:MaxIdentifierLength", 128);

            SqlServerModelBuilderExtensions.UseIdentityColumns(modelBuilder, 1L, 1);

            modelBuilder.Entity("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Category", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<string>("Name")
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Categories");

                    b.HasData(
                        new
                        {
                            Id = 1,
                            Name = "Laptops"
                        },
                        new
                        {
                            Id = 2,
                            Name = "PC's"
                        },
                        new
                        {
                            Id = 3,
                            Name = "Phones"
                        });
                });

            modelBuilder.Entity("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Product", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<int>("CategoryId")
                        .HasColumnType("int");

                    b.Property<string>("Image")
                        .HasColumnType("nvarchar(max)");

                    b.Property<string>("Name")
                        .HasColumnType("nvarchar(max)");

                    b.Property<decimal>("Price")
                        .HasColumnType("money");

                    b.HasKey("Id");

                    b.HasIndex("CategoryId");

                    b.ToTable("Products");

                    b.HasData(
                        new
                        {
                            Id = 1,
                            CategoryId = 3,
                            Image = "phone.jpg",
                            Name = "Samsung L7",
                            Price = 456.23m
                        },
                        new
                        {
                            Id = 2,
                            CategoryId = 3,
                            Image = "phone.jpg",
                            Name = "Redmi Note7",
                            Price = 325.13m
                        },
                        new
                        {
                            Id = 3,
                            CategoryId = 1,
                            Image = "laptop.jpg",
                            Name = "Dell Latitude",
                            Price = 1456.23m
                        },
                        new
                        {
                            Id = 4,
                            CategoryId = 2,
                            Image = "laptop.jpg",
                            Name = "Dell Desktop",
                            Price = 856.3m
                        },
                        new
                        {
                            Id = 5,
                            CategoryId = 1,
                            Image = "laptop.jpg",
                            Name = "IBook 7",
                            Price = 2456.00m
                        },
                        new
                        {
                            Id = 6,
                            CategoryId = 3,
                            Image = "tablet.jpg",
                            Name = "Ipad12",
                            Price = 958.23m
                        });
                });

            modelBuilder.Entity("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Property", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("int");

                    SqlServerPropertyBuilderExtensions.UseIdentityColumn(b.Property<int>("Id"), 1L, 1);

                    b.Property<string>("Name")
                        .HasColumnType("nvarchar(max)");

                    b.HasKey("Id");

                    b.ToTable("Properties");

                    b.HasData(
                        new
                        {
                            Id = 1,
                            Name = "Basic"
                        },
                        new
                        {
                            Id = 2,
                            Name = "Luxury"
                        },
                        new
                        {
                            Id = 3,
                            Name = "Student"
                        },
                        new
                        {
                            Id = 4,
                            Name = "Family"
                        },
                        new
                        {
                            Id = 5,
                            Name = "Office"
                        });
                });

            modelBuilder.Entity("ProductProperty", b =>
                {
                    b.Property<int>("ProductsId")
                        .HasColumnType("int");

                    b.Property<int>("PropertiesId")
                        .HasColumnType("int");

                    b.HasKey("ProductsId", "PropertiesId");

                    b.HasIndex("PropertiesId");

                    b.ToTable("ProductProperty");

                    b.HasData(
                        new
                        {
                            ProductsId = 1,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 1,
                            PropertiesId = 2
                        },
                        new
                        {
                            ProductsId = 1,
                            PropertiesId = 3
                        },
                        new
                        {
                            ProductsId = 2,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 2,
                            PropertiesId = 2
                        },
                        new
                        {
                            ProductsId = 2,
                            PropertiesId = 3
                        },
                        new
                        {
                            ProductsId = 3,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 3,
                            PropertiesId = 3
                        },
                        new
                        {
                            ProductsId = 4,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 5,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 5,
                            PropertiesId = 3
                        },
                        new
                        {
                            ProductsId = 6,
                            PropertiesId = 1
                        },
                        new
                        {
                            ProductsId = 6,
                            PropertiesId = 2
                        });
                });

            modelBuilder.Entity("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Product", b =>
                {
                    b.HasOne("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Category", "Category")
                        .WithMany("Products")
                        .HasForeignKey("CategoryId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Category");
                });

            modelBuilder.Entity("ProductProperty", b =>
                {
                    b.HasOne("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Product", null)
                        .WithMany()
                        .HasForeignKey("ProductsId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.HasOne("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Property", null)
                        .WithMany()
                        .HasForeignKey("PropertiesId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();
                });

            modelBuilder.Entity("cu.ApiBAsics.Lesvoorbeeld.Avond.Core.Entities.Category", b =>
                {
                    b.Navigation("Products");
                });
#pragma warning restore 612, 618
        }
    }
}
