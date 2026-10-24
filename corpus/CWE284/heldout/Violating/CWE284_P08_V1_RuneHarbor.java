import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneHarbor {

    public void deleteRuneHarborAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_HARBOR_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneHarborSink()).applyRuneHarborDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneHarborSink {
    public void applyRuneHarborDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        try {
            PreparedStatement runeHarborDelete = runeHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHarborDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeHarborDelete.executeUpdate();
            }
        } finally {
            runeHarborConnection.close();
        }
    }
}
