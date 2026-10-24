import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberSundial {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberSundialAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberSundialSink()).applyAmberSundialDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberSundialSink {
    public void applyAmberSundialDeletion(CWE284_P09_V2_AmberSundial.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        try {
            PreparedStatement amberSundialDelete = amberSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberSundialDelete.setString(1, data);
            amberSundialDelete.executeUpdate();
        } finally {
            amberSundialConnection.close();
        }
    }
}
