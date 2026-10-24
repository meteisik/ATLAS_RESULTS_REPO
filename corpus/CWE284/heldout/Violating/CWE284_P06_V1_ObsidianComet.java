import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianComet {

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianCometSink()).applyObsidianCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianCometSink {
    public void applyObsidianCometDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            obsidianCometDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianCometConnection.close();
        }
    }
}
