import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronQuartzSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronQuartzSafeSink()).applySaffronQuartzDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronQuartzSafeSink {
    public void applySaffronQuartzDeletion(CWE284_P09_V1_SaffronQuartzSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        try {
            PreparedStatement saffronQuartzDelete = saffronQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronQuartzDelete.setString(1, data);
            if (authorized) {
                saffronQuartzDelete.executeUpdate();
            }
        } finally {
            saffronQuartzConnection.close();
        }
    }
}
