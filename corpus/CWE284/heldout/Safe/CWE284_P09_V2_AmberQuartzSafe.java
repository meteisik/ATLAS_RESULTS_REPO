import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberQuartzSafe {
    private static boolean privateTrue = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberQuartzAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("AMBER_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberQuartzSafeSink()).applyAmberQuartzDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberQuartzSafeSink {
    public void applyAmberQuartzDeletion(CWE284_P09_V2_AmberQuartzSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        try {
            PreparedStatement amberQuartzDelete = amberQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberQuartzDelete.setString(1, data);
            if (authorized) {
                amberQuartzDelete.executeUpdate();
            }
        } finally {
            amberQuartzConnection.close();
        }
    }
}
