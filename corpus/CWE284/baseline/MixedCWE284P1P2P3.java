package cwe284.mixed;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class MixedCWE284P1P2P3 {

    // Violation 1 (P01, Juliet _01): an account identifier is read from the
    // environment and its authorization decision is computed in the same
    // method, but the parameterized DELETE runs without consulting it.
    static class NorthAccounts {
        public void deleteNorthAccount() throws SQLException {
            String data;
            data = System.getenv("NORTH_ACCOUNT_ID");
            boolean authorized = isAuthorized(data);
            Connection northConnection = DriverManager.getConnection("jdbc:hsqldb:mem:north");
            try {
                PreparedStatement northDelete = northConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                northDelete.setString(1, data);
                northDelete.executeUpdate();
            } finally {
                northConnection.close();
            }
        }

        private boolean isAuthorized(String accountId) {
            String operator = System.getProperty("user.name");
            return operator != null && operator.equals(accountId);
        }
    }

    // Violation 2 (P02, Juliet _31): the account identifier and its decision
    // are copied to second locals inside a nested block; a later block re-reads
    // the copies and runs the parameterized DELETE before checking the decision.
    static class EastAccounts {
        public void deleteEastAccount() throws SQLException {
            String dataCopy;
            boolean authorizedCopy;
            {
                String data;
                data = System.getenv("EAST_ACCOUNT_ID");
                dataCopy = data;
                authorizedCopy = isAuthorized(data);
            }
            {
                String data = dataCopy;
                boolean authorized = authorizedCopy;
                Connection eastConnection = DriverManager.getConnection("jdbc:hsqldb:mem:east");
                try {
                    PreparedStatement eastDelete = eastConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                    eastDelete.setString(1, data);
                    eastDelete.executeUpdate();
                    if (!authorized) {
                        throw new SecurityException("delete of account " + data + " is not authorized");
                    }
                } finally {
                    eastConnection.close();
                }
            }
        }

        private boolean isAuthorized(String accountId) {
            String operator = System.getProperty("user.name");
            return operator != null && operator.equals(accountId);
        }
    }

    // Violation 3 (P03, Juliet _41): the account identifier and a decision are
    // passed to a private sink method of the same class, which runs the
    // parameterized DELETE only when the decision holds; the decision, however,
    // authorizes the requesting user rather than the account being deleted.
    static class SouthAccounts {
        public void deleteSouthAccount() throws SQLException {
            String data;
            data = System.getenv("SOUTH_ACCOUNT_ID");
            String requester = System.getProperty("user.name");
            boolean authorized = isAuthorized(requester);
            applySouthDeletion(data, authorized);
        }

        private void applySouthDeletion(String data, boolean authorized) throws SQLException {
            Connection southConnection = DriverManager.getConnection("jdbc:hsqldb:mem:south");
            try {
                PreparedStatement southDelete = southConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                southDelete.setString(1, data);
                if (authorized) {
                    southDelete.executeUpdate();
                }
            } finally {
                southConnection.close();
            }
        }

        private boolean isAuthorized(String accountId) {
            String operator = System.getProperty("user.name");
            return operator != null && operator.equals(accountId);
        }
    }

    // Safe (P01 safe twin): the same same-method flow, but the parameterized
    // DELETE only executes when the decision for this account holds.
    static class WestAccounts {
        public void deleteWestAccount() throws SQLException {
            String data;
            data = System.getenv("WEST_ACCOUNT_ID");
            boolean authorized = isAuthorized(data);
            Connection westConnection = DriverManager.getConnection("jdbc:hsqldb:mem:west");
            try {
                PreparedStatement westDelete = westConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                westDelete.setString(1, data);
                if (authorized) {
                    westDelete.executeUpdate();
                }
            } finally {
                westConnection.close();
            }
        }

        private boolean isAuthorized(String accountId) {
            String operator = System.getProperty("user.name");
            return operator != null && operator.equals(accountId);
        }
    }
}
