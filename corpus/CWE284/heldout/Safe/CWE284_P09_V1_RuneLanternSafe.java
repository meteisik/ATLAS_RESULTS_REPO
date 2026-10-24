import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneLanternSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneLanternAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneLanternSafeSink()).applyRuneLanternDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneLanternSafeSink {
    public void applyRuneLanternDeletion(CWE284_P09_V1_RuneLanternSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            if (authorized) {
                runeLanternDelete.executeUpdate();
            }
        } finally {
            runeLanternConnection.close();
        }
    }
}
