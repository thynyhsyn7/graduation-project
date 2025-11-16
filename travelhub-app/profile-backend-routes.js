// ==================== USER PROFILE ROUTES ====================
// Add these routes to your server.js file

// Change password
app.post('/api/user/change-password', isAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Current password and new password are required' 
            });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: 'New password must be at least 8 characters' 
            });
        }
        
        // Get user with password
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Verify current password
        const isPasswordValid = await user.comparePassword(currentPassword);
        
        if (!isPasswordValid) {
            return res.status(401).json({ 
                success: false, 
                message: 'Current password is incorrect' 
            });
        }
        
        // Update password
        user.password = newPassword;
        await user.save();
        
        res.json({ 
            success: true, 
            message: 'Password changed successfully' 
        });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Update own profile (any user can update their own profile)
app.put('/api/user/profile', isAuthenticated, async (req, res) => {
    try {
        const { firstName, lastName, email, phone, country } = req.body;
        
        const updateData = {};
        if (firstName) updateData.firstName = firstName;
        if (lastName) updateData.lastName = lastName;
        if (email) updateData.email = email.toLowerCase();
        if (phone) updateData.phone = phone;
        if (country) updateData.country = country;
        
        // Check if email is already taken by another user
        if (email) {
            const existingUser = await User.findOne({ 
                email: email.toLowerCase(), 
                _id: { $ne: req.session.userId } 
            });
            
            if (existingUser) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Email already in use by another account' 
                });
            }
        }
        
        const user = await User.findByIdAndUpdate(
            req.session.userId,
            updateData,
            { new: true }
        ).select('-password');
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Profile updated successfully', 
            user 
        });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// Get profile statistics (for admins)
app.get('/api/user/stats', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const stats = {
            memberSince: user.createdAt,
            lastLogin: user.lastLogin,
            emailVerified: user.isEmailVerified,
            accountStatus: user.isActive ? 'Active' : 'Inactive',
            role: user.role
        };
        
        // Add role-specific stats
        if (user.role === 'admin') {
            stats.totalUsers = await User.countDocuments();
            stats.pendingApprovals = await User.countDocuments({ 
                isApproved: false, 
                role: { $ne: 'customer' } 
            });
        } else if (user.role === 'hotel_owner') {
            stats.totalHotels = await Hotel.countDocuments({ owner: user._id });
            stats.totalBookings = await Booking.countDocuments({ 
                hotel: { $in: await Hotel.find({ owner: user._id }).select('_id') } 
            });
        } else if (user.role === 'ticket_owner') {
            stats.totalFlights = await Flight.countDocuments({ owner: user._id });
            stats.totalBookings = await Booking.countDocuments({ 
                flight: { $in: await Flight.find({ owner: user._id }).select('_id') } 
            });
        } else if (user.role === 'tour_company') {
            stats.totalTours = await Tour.countDocuments({ owner: user._id });
            stats.totalBookings = await Booking.countDocuments({ 
                tour: { $in: await Tour.find({ owner: user._id }).select('_id') } 
            });
        } else if (user.role === 'customer') {
            stats.totalBookings = await Booking.countDocuments({ user: user._id });
        }
        
        res.json({ success: true, stats });
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});