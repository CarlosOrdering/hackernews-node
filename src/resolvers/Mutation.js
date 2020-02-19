const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { APP_SECRET, getUserId } = require('../utils')

async function signup(parent, args, context, info) {
    // Encrypt the password
    const password = await bcrypt.hash(args.password, 10)
    // Use the prisma client to store user in database
    const user = await context.prisma.createUser({ ...args, password })
    // Generate JWT signed with APP_SECRET
    const token = jwt.sign({userId: user.id }, APP_SECRET)
    // Return roken and user, that adheres to shape of an AuthPayload object defined on Schema.graphql
    return {
        token,
        user
    }
}

async function login(parent, args, context, info) {
    // Retrive the existing user by email, if no user throw error
    const user = await context.prisma.user({email: args.email})
    if(!user) {
        throw new Error('No such user found')
    }
    // Compare provided password with the one StereoPannerNode, if not match throw error
    const valid = await bcrypt.compare(args.password, user.password)
    if(!valid) {
        throw new Error('Invalid password')
    }

    const token = jwt.sign({ userId: user.id }, APP_SECRET)
    // Return Authpayload shape
    return {
        token,
        user
    }
}

function post(parent, args, context, info) {
    const userId = getUserId(context)
    return context.prisma.createLink({
        url: args.url,
        description: args.description,
        postedBy: { connect: { id: userId } },
    })
}

module.exports = {
    signup,
    login,
    post
}