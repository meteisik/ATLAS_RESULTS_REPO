import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberPrismSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberPrismAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AMBER_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberPrismSafeSink()).applyAmberPrismDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberPrismSafeSink {
    public void applyAmberPrismDeletion(CWE284_P09_V2_AmberPrismSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        try {
            PreparedStatement amberPrismDelete = amberPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberPrismDelete.setString(1, data);
            if (authorized) {
                amberPrismDelete.executeUpdate();
            }
        } finally {
            amberPrismConnection.close();
        }
    }
}
