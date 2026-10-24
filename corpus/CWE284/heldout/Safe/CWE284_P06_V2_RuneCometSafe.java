import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneCometSafe {

    public void deleteRuneCometAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_COMET_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneCometSafeSink()).applyRuneCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneCometSafeSink {
    public void applyRuneCometDeletion(String data, boolean authorized) throws SQLException {
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        try {
            PreparedStatement runeCometDelete = runeCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeCometDelete.setString(1, data);
            if (authorized) {
                runeCometDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeCometConnection.close();
        }
    }
}
