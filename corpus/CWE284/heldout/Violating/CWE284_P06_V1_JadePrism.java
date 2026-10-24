import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadePrism {

    public void deleteJadePrismAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_PRISM_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadePrismSink()).applyJadePrismDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadePrismSink {
    public void applyJadePrismDeletion(String data, boolean authorized) throws SQLException {
        Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
        try {
            PreparedStatement jadePrismDelete = jadePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadePrismDelete.setString(1, data);
            jadePrismDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadePrismConnection.close();
        }
    }
}
