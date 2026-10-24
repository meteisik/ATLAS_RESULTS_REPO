import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronPrismSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronPrismAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_PRISM_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronPrismSafeSink()).applySaffronPrismDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronPrismSafeSink {
    public void applySaffronPrismDeletion(CWE284_P09_V1_SaffronPrismSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronPrism");
        try {
            PreparedStatement saffronPrismDelete = saffronPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronPrismDelete.setString(1, data);
            if (authorized) {
                saffronPrismDelete.executeUpdate();
            }
        } finally {
            saffronPrismConnection.close();
        }
    }
}
