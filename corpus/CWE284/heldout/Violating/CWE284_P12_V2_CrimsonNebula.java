import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonNebula {

    public void deleteCrimsonNebulaAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("CRIMSON_NEBULA_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonNebulaBase baseObject = new CWE284_P12_V2_CrimsonNebulaRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonNebulaBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonNebulaRemover extends CWE284_P12_V2_CrimsonNebulaBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonNebula");
        try {
            PreparedStatement crimsonNebulaDelete = crimsonNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonNebulaDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonNebulaDelete.executeUpdate();
            }
        } finally {
            crimsonNebulaConnection.close();
        }
    }
}
