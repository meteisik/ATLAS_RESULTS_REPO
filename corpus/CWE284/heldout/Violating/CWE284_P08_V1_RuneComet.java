import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_RuneComet {

    public void deleteRuneCometAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_COMET_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_RuneCometSink()).applyRuneCometDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_RuneCometSink {
    public void applyRuneCometDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        try {
            PreparedStatement runeCometDelete = runeCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeCometDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                runeCometDelete.executeUpdate();
            }
        } finally {
            runeCometConnection.close();
        }
    }
}
