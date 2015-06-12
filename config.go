package validation

import (
	"errors"
	"os"
	"strconv"
	"regexp"
	"tangacg.com/xmlnode"
)

const (
	DEFAULT_CONFIG_FILE_NAME = "vzhang-validation.xml"
	DEFAULT_FILE_PERMISSIONS os.FileMode = 0666	
)

type configuration struct {
	shieldingWordsNode   *xmlnode.Node
	fieldVerifyRulesNode *xmlnode.Node
}

func InitWithConfigFile(fileName string) error {
	if fieldRules != nil {
		return nil
	}
	if fileName == "" {
		fileName = DEFAULT_CONFIG_FILE_NAME	
	}
	cfgFile, err := os.OpenFile(fileName, os.O_RDONLY, DEFAULT_FILE_PERMISSIONS)
	if err != nil {
		return err
	}
	defer cfgFile.Close()
	
	var rootNode *xmlnode.Node
	rootNode, err = xmlnode.UnmarshalConfig(cfgFile)
	if err != nil {
		return err
	}
	if rootNode.Name != "vzhang-validation" || !rootNode.HasChildren() {
		return errors.New("config file error: the root element is not vzhang-validation or has no child element at file " + fileName)
	}
	config := new(configuration)
	for _, node := range rootNode.Children {
		switch node.Name {
			case "shielding-words":
				if config.shieldingWordsNode != nil {
					return errors.New("there must be only one shielding-words element")
				}
				config.shieldingWordsNode = node
			case "field-validation-rules":
				if config.fieldVerifyRulesNode != nil {
					return errors.New("there must be only one field-validation-rules element")
				}
				config.fieldVerifyRulesNode = node
			default:	
				return errors.New("there was a disallowed element named " + node.String())
		}
	}
	if config.fieldVerifyRulesNode == nil {
		return errors.New("there was no field-validation-rules element")
	}
	if config.shieldingWordsNode == nil {
		err = config.initShieldingWords()
		if err != nil {
			return err
		}
	} else {
		shieldingWords = make([]string, 0)
	}
	err = config.initFieldValidationRules()
	if err != nil {
		return err
	}
	return nil
}

func (config *configuration)initShieldingWords() error {
	shieldingWords = make([]string, 0)
	for _, node := range config.shieldingWordsNode.Children {
		switch node.Name {
			case "words":
				for _, wordNode := range node.Children {
					if wordNode.Name != "word" {
						return errors.New("there was disallowed element " + wordNode.String())
					}
					shieldingWords = append(shieldingWords, wordNode.Value)
				}
			default:
				return errors.New("there was disallowed element " + node.String())
		}
	}
	return nil
}

func (config *configuration)initFieldValidationRules() (err error) {
	fieldRules = make(map[string]*fieldRule, 0)
	for _, node := range config.fieldVerifyRulesNode.Children {
		if node.Name != "field" {
			return errors.New("there was disallowed element named " + node.Name)
		}
		rule := new(fieldRule)
		fieldName, ok := node.Attributes["name"]
		if !ok {
			return errors.New(node.Name + " element error: there must be name attribute")
		}
		_, ok = fieldRules[fieldName]
		if ok {
			return errors.New(node.Name + " element error: the name attribute's value was repeated")
		}
		rule.name = fieldName
		
		useRegExpStr, ok := node.Attributes["regexp"]
		if ok {
			rule.useRegExp, err = strconv.ParseBool(useRegExpStr)
			if err != nil {
				return errors.New(node.Name + " element error: the regexp attribute's value must be bool value")
			}
		} else {
			rule.useRegExp = false
		}
		
		requiredStr, ok := node.Attributes["required"]
		if ok {
			rule.isRequired, err = strconv.ParseBool(requiredStr)
			if err != nil {
				return errors.New(node.Name + " element error: the required attribute's value must be bool value")
			}
		} else {
			rule.isRequired = false
		}
		
		hashStr, ok := node.Attributes["hash"]
		if ok {
			rule.isHash, err = strconv.ParseBool(hashStr)
			if err != nil {
				return errors.New(node.Name + " element error: the hash attribute's value must be bool value")
			}
		} else {
			rule.isHash = false
		}
		
		shieldingStr, ok := node.Attributes["shielding"]
		if ok {
			rule.useShielding, err = strconv.ParseBool(shieldingStr)
			if err != nil {
				return errors.New(node.Name + " element error: the shielding attribute's value must be bool value")
			}
		} else {
			rule.useShielding = false
		}
		
		encryptStr, ok := node.Attributes["encrypt"]
		if ok {
			rule.needEncrypt, err = strconv.ParseBool(encryptStr)
			if err != nil {
				return errors.New(node.Name + " element error: the encrypt attribute's value must be bool value")
			}
		} else {
			rule.needEncrypt = false
		}
		
		if !node.HasChildren() {
			return errors.New(node.Name + " element must be have children")
		}
		
		rule.disAllowedList = make([]string, 0)
		for _, cnode := range node.Children {
			switch cnode.Name {
				case "maxlength":
					if rule.maxLength > 0 {
						return errors.New(node.Name + " element error: there must be only one maxlength element")
					}
					length, err := strconv.ParseUint(cnode.Value, 10, 32)
					if err != nil {
						return errors.New(node.Name + " element error: maxlength's value is illegal")
					}
					rule.maxLength = uint(length)
				case "minlength":
					if rule.minLength > 0 {
						return errors.New(node.Name + " element error: there must be only one minlength element")	
					}
					length, err := strconv.ParseUint(cnode.Value, 10, 32)
					if err != nil {
						return errors.New(node.Name + " element error: minlength's value is illegal")
					}
					rule.minLength = uint(length)
				case "regular-expression":
					if rule.regExpStr != "" {
						return errors.New(node.Name + " element error: there must be only one regular-expression element")	
					}
					rule.regExpStr = cnode.Value
					//预编译
					if rule.useRegExp {
						rule.regExp, err = regexp.Compile(rule.regExpStr)
						if err != nil {
							return errors.New(node.Name + " element error: regular-expression's value is illegal")
						}
					}
				case "encrypt-salt":
					if rule.encryptSalt != "" {
						return errors.New(node.Name + " element error: there must be only one encrypt-salt element")	
					}
					rule.encryptSalt = cnode.Value
				case "disallowed":
					rule.disAllowedList = append(rule.disAllowedList, cnode.Value)
				default:
					return errors.New(node.Name + " element error: there was a disallowed child element named " + cnode.Name)
			}
		}
		if rule.useRegExp && rule.regExp == nil {
			return errors.New(node.Name + " element error: there must be child element named regular-expression")
		}
		fieldRules[rule.name] = rule
	}
	return nil
}