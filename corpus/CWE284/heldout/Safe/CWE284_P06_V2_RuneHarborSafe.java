import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneHarborSafe {

    public void deleteRuneHarborAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("RUNE_HARBOR_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneHarborSafeSink()).applyRuneHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneHarborSafeSink {
    public void applyRuneHarborDeletion(String data, boolean authorized) throws SQLException {
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        try {
            PreparedStatement runeHarborDelete = runeHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHarborDelete.setString(1, data);
            if (authorized) {
                runeHarborDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeHarborConnection.close();
        }
    }
}
