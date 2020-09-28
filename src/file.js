/**
 * Copyright (c) 2017-2020, Neap Pty Ltd.
 * All rights reserved.
 * 
 * This source code is licensed under the BSD-style license.
*/

const fs = require('fs')
const { resolve } = require('path')

/**
 * Checks if a file or folder exists
 * 
 * @param  {String}  filePath 	Absolute path to file or folder on the local machine
 * @return {Boolean}   
 */
const fileExists = filePath => new Promise(onSuccess => fs.exists(filePath, yes => onSuccess(yes ? true : false)))

/**
 * Creates file or update file located under 'filePath'. 
 * 
 * @param  {String}  filePath 			Absolute file path on the local machine
 * @param  {Object}  content 			File content
 * @param  {Boolean} options.append 	Default false. If true, this function appends rather than overrides.
 * @param  {String}  options.appendSep 	Default '\n'. That the string used to separate appended content. This option is only
 *                                     	active when 'options.append' is set to true.
 * @return {Void}                	
 */
const writeToFile = (filePath, content, options) => new Promise((onSuccess, onFailure) => {
	content = content || ''
	const { append, appendSep='\n' } = options || {}
	const stringContent = (typeof(content) == 'string' || content instanceof Buffer) ? content : JSON.stringify(content, null, '  ')
	const fn = append ? fs.appendFile : fs.writeFile
	fn(filePath, append ? `${stringContent}${appendSep}` : stringContent, err => err ? onFailure(err) : onSuccess())
})

/**
 * Gets a file under a Google Cloud Storage's 'filePath'.
 * 
 * @param  {String}  filePath 	Absolute file path on the local machine
 * @return {Buffer}
 */
const readFile = filePath => new Promise((onSuccess, onFailure) => fs.readFile(filePath, (err, data) => err ? onFailure(err) : onSuccess(data)))

/**
 * Gets the absolute path. If not input is passed, it returns the current working directory. Supports both Windows and Unix OSes. 
 * 
 * @param  {String} somePath Some absolute or relative file or folder path.
 * @return {String}          Absolute path
 */
const getAbsolutePath = somePath => {
	if (!somePath)
		return process.cwd()
	else if (somePath.match(/^\./)) 
		return resolve(somePath)
	else if (somePath.match(/^(\\|\/|~)/)) 
		return somePath
	else if (typeof(somePath) == 'string')
		return resolve(somePath)
	else
		throw new Error(`Invalid path ${somePath}`)
}

/**
 * Gets a JSON object loacted under 'filePath'. This method is an alternative to 'require(filePath)' which caches results and prevents
 * to get access to a refreshed version of the JSON file. 
 * 
 * @param  {String} filePath			Absolute path to the JSON file. 
 * @param  {String} defaultValue		Default is {}
 * 
 * @return {Object}          			JSON Object
 */
const getJSON = (filePath, defaultValue={}) => readFile(filePath).then(text => {
	if (!text || !text.length)
		return defaultValue

	try {
		return JSON.parse(text.toString()) || defaultValue
	} catch(e) {
		return (() => ({}))(e)
	}
})

const getUniqueFileName = async filename => {
	if (!filename)
		throw new Error('Missing required \'filename\'')

	let [ext, ...fileParts] = filename.split('.').reverse()

	// Deals with extensionless file
	if (!fileParts.length) {
		fileParts.push(ext)
		ext = ''
	}

	const file = fileParts.join('.')
	let uniqueFilename = [file,ext].filter(x => x).join('.')

	let exists = true
	let counter = 0
	while (exists && counter < 100) {
		exists = await fileExists(getAbsolutePath(uniqueFilename))
		if (exists)
			uniqueFilename = [`${file}(${++counter})`,ext].filter(x => x).join('.')
	}

	if (counter == 100 && !exists)
		throw new Error(`${filename} exceeded the maximum number of similar file (100). Please try a different file name.`)

	return getAbsolutePath(uniqueFilename)
}

module.exports = {
	getUniqueFileName,
	read: readFile,
	write: writeToFile,
	exists: fileExists,
	json: {
		'get': getJSON,
		write: (filePath, obj) => writeToFile(filePath, obj)
	},
	getAbsolutePath
}