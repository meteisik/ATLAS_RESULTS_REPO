import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneHarborSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneHarborAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_HARBOR_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneHarborSafeSink()).applyRuneHarborDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneHarborSafeSink {
    public void applyRuneHarborDeletion(CWE284_P09_V1_RuneHarborSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        try {
            PreparedStatement runeHarborDelete = runeHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHarborDelete.setString(1, data);
            if (authorized) {
                runeHarborDelete.executeUpdate();
            }
        } finally {
            runeHarborConnection.close();
        }
    }
}
