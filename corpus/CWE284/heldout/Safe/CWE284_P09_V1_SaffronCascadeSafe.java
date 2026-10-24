import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronCascadeSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_CASCADE_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronCascadeSafeSink()).applySaffronCascadeDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronCascadeSafeSink {
    public void applySaffronCascadeDeletion(CWE284_P09_V1_SaffronCascadeSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        try {
            PreparedStatement saffronCascadeDelete = saffronCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCascadeDelete.setString(1, data);
            if (authorized) {
                saffronCascadeDelete.executeUpdate();
            }
        } finally {
            saffronCascadeConnection.close();
        }
    }
}
