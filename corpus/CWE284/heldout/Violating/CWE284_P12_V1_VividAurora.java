import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VividAurora {

    public void deleteVividAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("VIVID_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VividAuroraBase baseObject = new CWE284_P12_V1_VividAuroraRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VividAuroraBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VividAuroraRemover extends CWE284_P12_V1_VividAuroraBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection vividAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividAurora");
        try {
            PreparedStatement vividAuroraDelete = vividAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividAuroraDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividAuroraDelete.executeUpdate();
            }
        } finally {
            vividAuroraConnection.close();
        }
    }
}
