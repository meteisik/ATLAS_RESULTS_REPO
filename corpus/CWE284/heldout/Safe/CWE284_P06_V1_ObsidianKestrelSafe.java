import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianKestrelSafe {

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianKestrelSafeSink()).applyObsidianKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianKestrelSafeSink {
    public void applyObsidianKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        try {
            PreparedStatement obsidianKestrelDelete = obsidianKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianKestrelDelete.setString(1, data);
            if (authorized) {
                obsidianKestrelDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianKestrelConnection.close();
        }
    }
}
