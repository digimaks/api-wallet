// SPDX-License-Identifier: EUPL-1.2

//nolint:tagliatelle
package object

type PidData struct {
	GivenName                    string `json:"given_name"`
	FamilyName                   string `json:"family_name"`
	Nationality                  string `json:"nationality"`
	BirthDate                    string `json:"birth_date"`
	PersonalAdministrativeNumber string `json:"personal_administrative_number"`
	BirthPlace                   string `json:"birth_place"`
	BirthCountry                 string `json:"birth_country"`
	IssuingAuthority             string `json:"issuing_authority"`
	IssuingCountry               string `json:"issuing_country"`
	AgeOver18                    bool   `json:"age_over_18"`
}
