import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianKestrel {

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianKestrelSink()).applyObsidianKestrelDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianKestrelSink {
    public void applyObsidianKestrelDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        try {
            PreparedStatement obsidianKestrelDelete = obsidianKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianKestrelDelete.executeUpdate();
            }
        } finally {
            obsidianKestrelConnection.close();
        }
    }
}
