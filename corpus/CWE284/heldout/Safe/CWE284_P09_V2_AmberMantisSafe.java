import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberMantisSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberMantisAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("AMBER_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberMantisSafeSink()).applyAmberMantisDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberMantisSafeSink {
    public void applyAmberMantisDeletion(CWE284_P09_V2_AmberMantisSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            if (authorized) {
                amberMantisDelete.executeUpdate();
            }
        } finally {
            amberMantisConnection.close();
        }
    }
}
