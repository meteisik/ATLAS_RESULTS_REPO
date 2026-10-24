import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeMantis {
    private static int privateFive = 5;

    private void applyJadeMantisDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
        try {
            PreparedStatement jadeMantisDelete = jadeMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeMantisDelete.setString(1, data);
            if (authorized) {
                jadeMantisDelete.executeUpdate();
            }
        } finally {
            jadeMantisConnection.close();
        }
    }

    public void deleteJadeMantisAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("JADE_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyJadeMantisDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
