import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronSundial {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronSundialAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_SUNDIAL_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronSundialSink()).applySaffronSundialDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronSundialSink {
    public void applySaffronSundialDeletion(CWE284_P09_V1_SaffronSundial.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSundial");
        try {
            PreparedStatement saffronSundialDelete = saffronSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSundialDelete.setString(1, data);
            saffronSundialDelete.executeUpdate();
        } finally {
            saffronSundialConnection.close();
        }
    }
}
