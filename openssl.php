<?php

class OpenSSL{
	
	private $key = null;
	private $pubKey = null;
	private $csr = null;
	private $crt = null;
	private $caKey = null;
	private $caCsr = null;
	private $caCrt = null;

	public $keyConf = [
					    "private_key_bits" => 2048,
					    "private_key_type" => OPENSSL_KEYTYPE_RSA,
						];
	public $csrConf = [
					    "countryName" => "CN",
					    "stateOrProvinceName" => "SH",
					    "localityName" => "SH",
					    "organizationName" => "OR",
					    "organizationalUnitName" => "OR",
					    "commonName" => "127.0.0.1",
					    "emailAddress" => "example@example.com"
						];


	public function __construct(){
		extension_loaded('openssl') or die('php need openssl module');

	}
	public function set_key($path){
		$this->key = $this->get_file($path);
	}
	public function set_csr($path){
		$this->csr = $this->get_file($path);
	}
	public function set_crt($path){
		$this->crt = $this->get_file($path);
	}
	public function set_caKey($path){
		$this->caKey = $this->get_file($path);
	}
	public function set_caCrt($path){
		$this->caCrt = $this->get_file($path);
	}

	public function get_key($pathName){
		openssl_pkey_export_to_file($this->key, $pathName);
	}
	public function get_csr($pathName){
		openssl_csr_export_to_file($this->csr, $pathName);
	}
	public function get_crt($pathName){
		openssl_x509_export_to_file($this->crt, $pathName);
	}
	public function get_caKey($pathName){
		openssl_pkey_export_to_file($this->caKey, $pathName);
	}
	public function get_caCrt($pathName){
		openssl_x509_export_to_file($this->caCrt, $pathName);
	}
	public function get_pk12($pathName){
		openssl_pkcs12_export_to_file($this->crt, $pathName, $this->key, $pass);
	}
	public function gen_key($path=null){
		$this->key = openssl_pkey_new($this->keyConf);
		if( $path ){
			$this->get_key($path);
		}
	}
	// public function gen_csr($pathName){
	public function gen_csr($path){
		($this->key) or die('empty privateKey');
		//最后配置项参考http://php.net/manual/en/function.openssl-csr-new.php
		$this->csr = openssl_csr_new($this->csrConf, $this->key, array('digest_alg' => 'sha256'));
		if( $path ){
			$this->get_csr($path);
		}
	}
	public function gen_pubKey1(){
		$this->pubKey = openssl_csr_get_public_key ($this->csr);
	}
	public function gen_pubKey2(){
		$this->pubKey = openssl_pkey_get_public ($this->crt);
	}
	// public function gen_caKey($path){
	// }
	// public function gen_caCrt($path){
	// }
	public function sign($path){
		$vali = ['csr', 'caCrt', 'caKey'];
		$this->vEmp($vali);
		$this->crt = openssl_csr_sign( $this->csr, $this->caCrt, $this->caKey, $days=365, array('digest_alg' => 'sha256') );
		openssl_x509_export_to_file($this->crt, $path);
	}

	public function gen_pk12($pathName, $pass=''){
		openssl_pkcs12_export_to_file($this->crt, $pathName, $this->key, $pass);
	}

	//encode and decode
	public function encrypt_public($data){
		openssl_public_encrypt($data, $encrypted, $this->pubKey);
		return $encrypted;
	}
	public function decrypt_private($publicEncrypted){
		openssl_private_decrypt($publicEncrypted, $decrypted, $this->key);
		return $decrypted;
	}
	public function encrypt_private($data){
		openssl_private_encrypt($data, $encrypted, $this->key); 
		return $encrypted;
	}
	public function decrypt_public($privateEncrypted){
		openssl_public_decrypt($privateEncrypted, $decrypted, $this->pubKey);
		return $decrypted;
	}


	//******** tools ********
	public function get_file($path){
		(file_exists($path)) or die('no file in the directory');
		return file_get_contents($path);
	}
	public function validate_array($ori, $repl){
		foreach( $ori as $k => $v ){
			if( array_key_exists($k, $repl) ){
				$ori[$k] = $repl[$k];
			}
		}
		return $ori;
	}
	public function vEmp($vali){
		foreach( $vali as $k => $v ){
			( $this->{$v} ) or die ( $v.' is empty' );
		}
	}
}

$dir = __DIR__;
$ssl = new OpenSSL();
$ssl->gen_key($dir.'/server.key');
$ssl->gen_csr($dir.'/server.csr');
$ssl->set_caKey($dir.'/myCA.key');
$ssl->set_caCrt($dir.'/myCA.cer');
$ssl->sign($dir.'/server.crt');
$ssl->gen_pubKey1();
$ssl->gen_pubKey2();

$ssl->gen_pk12($dir.'/server.p12');

$str = 'Hello world!';
$enc = $ssl->encrypt_public($str);
var_dump($enc);
$dec = $ssl->decrypt_private($enc);
var_dump($dec);

$enc = $ssl->encrypt_private($str);
var_dump($enc);
$dec = $ssl->decrypt_public($enc);
var_dump($dec);