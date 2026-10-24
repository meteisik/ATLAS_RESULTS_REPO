import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneHelix {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneHelixAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_HELIX_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneHelixSink()).applyRuneHelixDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneHelixSink {
    public void applyRuneHelixDeletion(CWE284_P09_V1_RuneHelix.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        try {
            PreparedStatement runeHelixDelete = runeHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHelixDelete.setString(1, data);
            runeHelixDelete.executeUpdate();
        } finally {
            runeHelixConnection.close();
        }
    }
}
