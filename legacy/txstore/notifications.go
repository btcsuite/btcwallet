/*
 * Copyright (c) 2014 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package txstore

import (
	"errors"
)

// ErrDuplicateListen is returned for any attempts to listen for the same
// notification more than once.  If callers must pass along a notifiation to
// multiple places, they must broadcast it themself.
var ErrDuplicateListen = errors.New("duplicate listen")

type noopLocker struct{}

func (noopLocker) Lock()   {}
func (noopLocker) Unlock() {}

func (s *Store) updateNotificationLock() {
	switch {
	case s.newCredit == nil:
		fallthrough
	case s.newDebits == nil:
		fallthrough
	case s.minedCredit == nil:
		fallthrough
	case s.minedDebits == nil:
		return
	}
	s.notificationLock = noopLocker{}
}

// ListenNewCredits returns a channel that passes all Credits that are newly
// added to the transaction store.  The channel must be read, or other
// transaction store methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (s *Store) ListenNewCredits() (<-chan Credit, error) {
	s.notificationLock.Lock()
	defer s.notificationLock.Unlock()

	if s.newCredit != nil {
		return nil, ErrDuplicateListen
	}
	s.newCredit = make(chan Credit)
	s.updateNotificationLock()
	return s.newCredit, nil
}

// ListenNewDebits returns a channel that passes all Debits that are newly
// added to the transaction store.  The channel must be read, or other
// transaction store methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (s *Store) ListenNewDebits() (<-chan Debits, error) {
	s.notificationLock.Lock()
	defer s.notificationLock.Unlock()

	if s.newDebits != nil {
		return nil, ErrDuplicateListen
	}
	s.newDebits = make(chan Debits)
	s.updateNotificationLock()
	return s.newDebits, nil
}

// ListenMinedCredits returns a channel that passes all  that are moved
// from unconfirmed to a newly attached block.  The channel must be read, or
// other transaction store methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (s *Store) ListenMinedCredits() (<-chan Credit, error) {
	s.notificationLock.Lock()
	defer s.notificationLock.Unlock()

	if s.minedCredit != nil {
		return nil, ErrDuplicateListen
	}
	s.minedCredit = make(chan Credit)
	s.updateNotificationLock()
	return s.minedCredit, nil
}

// ListenMinedDebits returns a channel that passes all Debits that are moved
// from unconfirmed to a newly attached block.  The channel must be read, or
// other transaction store methods will block.
//
// If this is called twice, ErrDuplicateListen is returned.
func (s *Store) ListenMinedDebits() (<-chan Debits, error) {
	s.notificationLock.Lock()
	defer s.notificationLock.Unlock()

	if s.minedDebits != nil {
		return nil, ErrDuplicateListen
	}
	s.minedDebits = make(chan Debits)
	s.updateNotificationLock()
	return s.minedDebits, nil
}

func (s *Store) notifyNewCredit(c Credit) {
	s.notificationLock.Lock()
	if s.newCredit != nil {
		s.newCredit <- c
	}
	s.notificationLock.Unlock()
}

func (s *Store) notifyNewDebits(d Debits) {
	s.notificationLock.Lock()
	if s.newDebits != nil {
		s.newDebits <- d
	}
	s.notificationLock.Unlock()
}

func (s *Store) notifyMinedCredit(c Credit) {
	s.notificationLock.Lock()
	if s.minedCredit != nil {
		s.minedCredit <- c
	}
	s.notificationLock.Unlock()
}

func (s *Store) notifyMinedDebits(d Debits) {
	s.notificationLock.Lock()
	if s.minedDebits != nil {
		s.minedDebits <- d
	}
	s.notificationLock.Unlock()
}
