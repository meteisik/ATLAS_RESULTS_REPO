import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_RuneCometSafe {

    public void deleteRuneCometAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_RuneCometSafeChecker()).isAuthorized(data);
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        try {
            PreparedStatement runeCometDelete = runeCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeCometDelete.setString(1, data);
            if (authorized) {
                runeCometDelete.executeUpdate();
            }
        } finally {
            runeCometConnection.close();
        }
    }
}

class CWE284_P07_V1_RuneCometSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
