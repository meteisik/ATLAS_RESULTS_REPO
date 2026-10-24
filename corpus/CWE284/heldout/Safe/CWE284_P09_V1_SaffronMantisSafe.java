import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronMantisSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronMantisAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_MANTIS_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronMantisSafeSink()).applySaffronMantisDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronMantisSafeSink {
    public void applySaffronMantisDeletion(CWE284_P09_V1_SaffronMantisSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronMantis");
        try {
            PreparedStatement saffronMantisDelete = saffronMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronMantisDelete.setString(1, data);
            if (authorized) {
                saffronMantisDelete.executeUpdate();
            }
        } finally {
            saffronMantisConnection.close();
        }
    }
}
