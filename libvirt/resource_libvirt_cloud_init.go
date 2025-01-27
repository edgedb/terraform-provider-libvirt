package libvirt

import (
	"fmt"
	"log"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/cenkalti/backoff/v4"
)

func resourceCloudInitDisk() *schema.Resource {
	return &schema.Resource{
		Create: resourceCloudInitDiskCreate,
		Read:   resourceCloudInitDiskRead,
		Delete: resourceCloudInitDiskDelete,
		Exists: resourceCloudInitDiskExists,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"pool": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "default",
				ForceNew: true,
			},
			"user_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"meta_data": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"network_config": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
		},
	}
}

func resourceCloudInitDiskCreate(d *schema.ResourceData, meta interface{}) error {
	log.Printf("[DEBUG] creating cloudinit")

	client := meta.(*Client)
	if virConn := client.libvirt; virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	cloudInit := newCloudInitDef()
	cloudInit.UserData = d.Get("user_data").(string)
	cloudInit.MetaData = d.Get("meta_data").(string)
	cloudInit.NetworkConfig = d.Get("network_config").(string)
	cloudInit.Name = d.Get("name").(string)
	cloudInit.PoolName = d.Get("pool").(string)

	log.Printf("[INFO] cloudInit: %+v", cloudInit)

	iso, err := cloudInit.CreateIso()
	if err != nil {
		return err
	}
	key, err := cloudInit.UploadIso(client, iso)
	if err != nil {
		return err
	}
	d.SetId(key)

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxInterval = 1 * time.Second
	expBackoff.MaxElapsedTime = 5 * time.Second

	return backoff.Retry(
		func() error {
			return resourceCloudInitDiskRead(d, meta)
		},
		expBackoff,
	)
}

func resourceCloudInitDiskRead(d *schema.ResourceData, meta interface{}) error {
	virConn := meta.(*Client).libvirt
	if virConn == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	ci, err := newCloudInitDefFromRemoteISO(virConn, d.Id())
	if err != nil {
		return fmt.Errorf("error while retrieving remote ISO: %s", err)
	}
	d.Set("pool", ci.PoolName)
	d.Set("name", ci.Name)
	d.Set("user_data", ci.UserData)
	d.Set("meta_data", ci.MetaData)
	d.Set("network_config", ci.NetworkConfig)
	return nil
}

func resourceCloudInitDiskDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*Client)
	if client.libvirt == nil {
		return fmt.Errorf(LibVirtConIsNil)
	}

	key, err := getCloudInitVolumeKeyFromTerraformID(d.Id())
	if err != nil {
		return err
	}

	return volumeDelete(client, key)
}

func resourceCloudInitDiskExists(d *schema.ResourceData, meta interface{}) (bool, error) {
	log.Printf("[DEBUG] Check if resource libvirt_cloudinit_disk exists")
	client := meta.(*Client)
	if client.libvirt == nil {
		return false, fmt.Errorf(LibVirtConIsNil)
	}

	key, err := getCloudInitVolumeKeyFromTerraformID(d.Id())
	if err != nil {
		return false, err
	}

	volPoolName := d.Get("pool").(string)
	volume, err := volumeLookupReallyHard(client, volPoolName, key)
	if err != nil {
		return false, err
	}

	if volume == nil {
		return false, nil
	}

	return true, nil
}
