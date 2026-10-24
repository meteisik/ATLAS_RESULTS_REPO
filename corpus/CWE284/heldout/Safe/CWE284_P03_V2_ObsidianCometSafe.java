import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianCometSafe {

    private void applyObsidianCometDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            if (authorized) {
                obsidianCometDelete.executeUpdate();
            }
        } finally {
            obsidianCometConnection.close();
        }
    }

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyObsidianCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
