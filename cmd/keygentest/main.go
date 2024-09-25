package main

import (
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/test"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = 3
	testThreshold    = 1
)

const (
	testFixtureDirFormat  = "%s/_fixtures"
	testFixtureFileFormat = "keygen_data_%d_%d.json"
)

func timer(name string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s took %v\n", name, time.Since(start))
	}
}

func printPreParams(p *keygen.LocalPreParams) {
	log.Printf("PaillierSK:%s,%s,%s,%s\n", p.PaillierSK.N.String(), p.PaillierSK.PhiN.String(), p.PaillierSK.P.String(), p.PaillierSK.Q.String())
	log.Printf("NTildei %s\n", p.NTildei)
	log.Printf("H1i %s, H2i%s\n", p.H1i.String(), p.H2i.String())
	log.Printf("Alpha %s\n", p.Alpha.String())
	log.Printf("Beta %s\n", p.Beta.String())
	log.Printf("P %s\n", p.P.String())
	log.Printf("Q %s\n", p.Q.String())
}

func main() {
	defer timer("main")()
	//testDistibutedSigning()
	//return

	var preParams [3]*keygen.LocalPreParams

	preParams[0], _ = keygen.GeneratePreParams(1 * time.Minute)
	preParams[1], _ = keygen.GeneratePreParams(1 * time.Minute)
	preParams[2], _ = keygen.GeneratePreParams(1 * time.Minute)

	testKeyGen(preParams[:], 1)
	preParams[0], _ = keygen.GeneratePreParams(1 * time.Minute)
	//preParams[1], _ = keygen.GeneratePreParams(1 * time.Minute)
	//preParams[2], _ = keygen.GeneratePreParams(1 * time.Minute)
	testKeyGen(preParams[:], 2)
}

func testKeyGen(preParams []*keygen.LocalPreParams, stage int) {
	pIDs := tss.SortPartyIDs(getParticipantPartyIDs())

	/*
		// Set up the parameters
		// Note: The `id` and `moniker` fields are for convenience to allow you to easily track participants.
		// The `id` should be a unique string representing this party in the network and `moniker` can be anything (even left blank).
		// The `uniqueKey` is a unique identifying key for this peer (such as its p2p public key) as a big.Int.
		id := "1234567890"
		moniker := "0987654321"
		uniqueKey := big.NewInt(77886654)
		thisParty := tss.NewPartyID(id, moniker, uniqueKey)
	*/

	p2pCtx := tss.NewPeerContext(pIDs)

	// Select an elliptic curve
	// use ECDSA
	//curve := tss.S256()

	//threshold := 2
	/*
		params := tss.NewParameters(curve, ctx, thisParty, len(parties), threshold)

		// You should keep a local mapping of `id` strings to `*PartyID` instances so that an incoming message can have its origin party's `*PartyID` recovered for passing to `UpdateFromBytes` (see below)
		partyIDMap := make(map[string]*tss.PartyID)
		for _, id := range parties {
			partyIDMap[id.Id] = id
		}
	*/

	parties := make([]*keygen.LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan *keygen.LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater
	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *keygen.LocalParty
		tmp := big.NewInt(0)
		tmp = tmp.SetBytes(pIDs[i].Key)
		log.Printf("Index %d, Key %s\n", i, tmp.String())
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), testThreshold)
		P = keygen.NewLocalParty(params, outCh, endCh, *preParams[i]).(*keygen.LocalParty)

		parties = append(parties, P)
		//		go func(P *keygen.LocalParty) {
		//			if err := P.Start(); err != nil {
		//				errCh <- err
		//				log.Printf("Error %s", err.Error())
		//			}
		//		}(P)
	}

	for _, P := range parties {
		go func(P *keygen.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
				log.Printf("Error %s", err.Error())
			}
		}(P)
	}

	/*
		party := keygen.NewLocalParty(params, outCh, endCh, *preParams) // Omit the last arg to compute the pre-params in round 1
		go func() {
			err := party.Start()
			// handle err ...
			errCh <- err
		}()
	*/
	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Printf("Error: %s", err)
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					fmt.Errorf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, _ := save.OriginalIndex()
			tryWriteTestFixtureFile(index, save, stage)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				fmt.Printf("Done. Received save data from %d participants", ended)
				fmt.Printf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}

}

func getParticipantPartyIDs() tss.UnSortedPartyIDs {
	ids := generateParticipantPartyIDs(3)
	return ids
}

// GenerateTestPartyIDs generates a list of mock PartyIDs for tests
func generateParticipantPartyIDs(count int, startAt ...int) tss.UnSortedPartyIDs {
	ids := make(tss.UnSortedPartyIDs, 0, count)
	key := common.MustGetRandomInt(cryptorand.Reader, 256)
	frm := 0
	i := 0 // default `i`
	if len(startAt) > 0 {
		frm = startAt[0]
		i = startAt[0]
	}
	for ; i < count+frm; i++ {
		ids = append(ids, &tss.PartyID{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      fmt.Sprintf("%d", i+1),
				Moniker: fmt.Sprintf("P[%d]", i+1),
				Key:     new(big.Int).Sub(key, big.NewInt(int64(count)-int64(i))).Bytes(),
			},
			Index: i,
			// this key makes tests more deterministic
		})
	}
	return ids //SortPartyIDs(ids, startAt...)
}

func makeTestFixtureFilePath(partyIndex int, stage int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName)

	log.Printf("File dir %s\n", fixtureDirName)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex, stage)
}

func tryWriteTestFixtureFile(index int, data *keygen.LocalPartySaveData, stage int) {
	fixtureFileName := makeTestFixtureFilePath(index, stage)

	// fixture file does not already exist?
	// if it does, we won't re-create it here
	fi, err := os.Stat(fixtureFileName)
	if !(err == nil && fi != nil && !fi.IsDir()) {
		fd, err := os.OpenFile(fixtureFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Printf("unable to open fixture file %s for writing", fixtureFileName)
		}
		bz, err := json.Marshal(&data)
		if err != nil {
			log.Printf("unable to marshal save data for fixture file %s", fixtureFileName)
		}
		_, err = fd.Write(bz)
		if err != nil {
			log.Printf("unable to write to fixture file %s", fixtureFileName)
		}
		log.Printf("Saved a test fixture file for party %d: %s", index, fixtureFileName)
	} else {
		log.Printf("Fixture file already exists for party %d; not re-creating: %s", index, fixtureFileName)
	}
	//
}

func LoadKeygenTestFixturesRandomSet(qty, fixtureCount int) ([]keygen.LocalPartySaveData, tss.SortedPartyIDs, error) {
	log.Printf("Loading %d %d\n", qty, fixtureCount)
	keys := make([]keygen.LocalPartySaveData, 0, qty)
	plucked := make(map[int]interface{}, qty)
	for i := 0; len(plucked) < qty; i = (i + 1) % fixtureCount {
		_, have := plucked[i]
		if pluck := rand.Float32() < 0.5; !have && pluck {
			plucked[i] = new(struct{})
		}
	}
	for i := range plucked {
		fixtureFilePath := makeTestFixtureFilePath(i, 1)
		log.Printf("Read file %s\n", fixtureFilePath)
		bz, err := ioutil.ReadFile(fixtureFilePath)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not open the test fixture for party %d in the expected location: %s. run keygen tests first.",
				i, fixtureFilePath)
		}
		var key keygen.LocalPartySaveData
		if err = json.Unmarshal(bz, &key); err != nil {
			return nil, nil, errors.Wrapf(err,
				"could not unmarshal fixture data for party %d located at: %s",
				i, fixtureFilePath)
		}
		for _, kbxj := range key.BigXj {
			kbxj.SetCurve(tss.S256())
		}
		key.ECDSAPub.SetCurve(tss.S256())
		keys = append(keys, key)
	}
	partyIDs := make(tss.UnSortedPartyIDs, len(keys))
	j := 0
	for i := range plucked {
		key := keys[j]
		pMoniker := fmt.Sprintf("%d", i+1)
		partyIDs[j] = tss.NewPartyID(pMoniker, pMoniker, key.ShareID)
		j++
	}
	sortedPIDs := tss.SortPartyIDs(partyIDs)
	sort.Slice(keys, func(i, j int) bool { return keys[i].ShareID.Cmp(keys[j].ShareID) == -1 })
	return keys, sortedPIDs, nil
}

func testDistibutedSigning() {
	messageToSign := big.NewInt(42)

	keys, signPIDs, err := LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	if err != nil {
		common.Logger.Println("should load keygen fixtures")
	}

	// PHASE: signing
	// use a shuffled selection of the list of parties for this test
	// init the parties
	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*signing.LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan *common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)

		P := signing.NewLocalParty(messageToSign, params, keys[i], outCh, endCh).(*signing.LocalParty)
		parties = append(parties, P)
		go func(P *signing.LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Printf("Error: %s", err)
			assert.FailNow(nil, err.Error())
			break signing

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					common.Logger.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				common.Logger.Printf("Done. Received signature data from %d participants", ended)
				R := parties[0].GetBigR() //   parties[0].Temp.BigR
				r := parties[0].GetR()    //     parties[0].Temp.Rx
				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())

				modN := common.ModInt(tss.S256().Params().N)

				// BEGIN check s correctness
				sumS := big.NewInt(0)
				for _, p := range parties {
					//					sumS = modN.Add(sumS, p.Temp.Si)
					sumS = modN.Add(sumS, p.GetSI())
				}
				fmt.Printf("S: %s\n", sumS.String())
				// END check s correctness

				// BEGIN ECDSA verify
				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				ok := ecdsa.Verify(&pk, messageToSign.Bytes(), R.X(), sumS)
				assert.True(nil, ok, "ecdsa verify must pass")
				fmt.Print("ECDSA signing test done.")
				// END ECDSA verify
				break signing
			}
		}
	}

}
